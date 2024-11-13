#!/usr/bin/env python3

# Copyright (c) 2014, Jelmer Tiete <jelmer@tiete.be>.
# Copyright (c) 2024, SMLIGHT <smartlight.email@gmail.com>
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at

#        http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import argparse
import glob
import logging
import re

import coloredlogs
from tqdm.asyncio import tqdm

from . import __version__
from .command import Bootloader, CommandInterface
from .const import MAX_BLOCK_SIZE
from .device import CC26xx
from .exceptions import CliException
from .firmware import FirmwareFile

# Serial boot loader over UART for CC13xx / CC26xx
# Based on the info found in TI's swru333a.pdf (spma029.pdf)
#
# Bootloader only starts if no valid image is found or if boot loader
# backdoor is enabled.
# Make sure you don't lock yourself out!! (enable backdoor in your firmware)
# More info at https://github.com/JelmerT/cc2538-bsl


_LOGGER = logging.getLogger(__name__)


class CLI:
    def __init__(self):
        self.parser = argparse.ArgumentParser(prog="smlight_cc_flasher")
        self.args = self.cli_setup()
        self.validate_args(self.args)

    def config_logging(self, log_level):
        coloredlogs.install(level=log_level, milliseconds=True)

    def validate_device(self, value):
        windows_pattern = r"^COM\d+$"
        linux_pattern = r"^/dev/tty(USB|ACM|S)\d+$"
        macos_pattern = r"^/dev/tty\.(usbserial|usbmodem)[A-Za-z0-9.-]+$"
        socket_pattern = r"^socket://[A-Za-z0-9.-]+:\d+$"

        if (
            re.match(windows_pattern, value)
            or re.match(linux_pattern, value)
            or re.match(macos_pattern, value)
            or re.match(socket_pattern, value)
        ):
            return value
        else:
            raise argparse.ArgumentTypeError(
                f"Invalid device format: {value}. "
                "Must be a serial port (e.g., COM7, /dev/ttyUSB0, "
                "/dev/tty.usbserial-1234) or a network socket (e.g., socket://host.local:9933)."
            )

    def cli_setup(self):
        parser = self.parser

        parser.add_argument("-q", action="store_true", help="Quiet")
        parser.add_argument("-V", action="store_true", help="Verbose")
        parser.add_argument(
            "-f",
            "--force",
            action="store_true",
            help="Force operation(s) which are not safe",
        )
        parser.add_argument(
            "-e", "--erase", action="store_true", help="Erase device before flashing"
        )
        parser.add_argument("-w", "--write", action="store_true", help="Write")
        parser.add_argument(
            "-v", "--verify", action="store_true", help="Verify (CRC32 check)"
        )
        parser.add_argument("-r", "--read", action="store_true", help="Read")
        parser.add_argument(
            "-l",
            "--len",
            type=int,
            default=0x80000,
            help="Length of read (default: 0x%(default)x)",
        )
        parser.add_argument("-o", "--output", help="Output file for read data")
        parser.add_argument(
            "-d",
            "--device",
            type=self.validate_device,
            help="Serial port (/dev/tty*, COM<#> or socket://host:port)",
        )
        parser.add_argument("--host", help="Hostname or IP address")
        parser.add_argument(
            "-p",
            "--port",
            default=6638,
            help="Port number for network socket (default: %(default)s)",
        )
        parser.add_argument(
            "-b",
            "--baud",
            type=int,
            default=500000,
            help="Baudrate (default: %(default)s)",
        )
        parser.add_argument("-a", "--address", type=int, help="Target address")
        parser.add_argument(
            "-i", "--ieee-address", help="Set the secondary 64 bit IEEE address"
        )
        parser.add_argument(
            "--bootloader-reset",
            default="generic",
            choices=["generic", "none", "generic2", "network"],
            help="Bootloader mode",
        )
        parser.add_argument(
            "--bootloader-active-high",
            action="store_true",
            help="Use active high signals to enter bootloader",
        )
        parser.add_argument(
            "--bootloader-invert-lines",
            action="store_true",
            help="Inverts the use of RTS and DTR to enter bootloader",
        )

        parser.add_argument(
            "--m33", action="store_true", help="Cortex-M33 cc13x4/cc26x4 devices"
        )
        parser.add_argument(
            "--disable-bootloader",
            action="store_true",
            help="After finishing, disable the bootloader",
        )

        parser.add_argument(
            "--version", action="version", version="%(prog)s " + __version__
        )
        parser.add_argument("file")

        self.args = parser.parse_args()
        return self.args

    def validate_args(self, args):
        if args.read and not args.output:
            self.parser.error("--output is required when --read is specified")

        if args.read and not args.write and args.verify:
            self.parser.error("Verify after read not implemented.")

        if args.len < 0:
            self.parser.error("Length must be positive but %d was provided" % args.len)

        if args.V:
            self.config_logging("DEBUG")
        elif args.q:
            self.config_logging("WARNING")
        else:
            self.config_logging("INFO")

        if not (args.device or args.host):
            self.auto_port()

        if not args.device and args.host:
            args.device = f"socket://{args.host}:{args.port}"

    def auto_port(self):
        """Try to find the port automatically."""
        ports = []
        # use serial.tools.list_ports.comports() instead?
        # Get a list of all USB-like names in /dev
        for name in [
            "ttyACM",
            "tty.usbserial",
            "ttyUSB",
            "tty.usbmodem",
            "tty.SLAB_USBtoUART",
        ]:
            ports.extend(glob.glob("/dev/%s*" % name))

        ports = sorted(ports)

        if ports:
            # Found something - take it
            self.args.device = ports[0]
        else:
            raise Exception("No serial port found.")

    def parse_ieee_address(self, inaddr: str) -> int:
        """Convert an entered IEEE address into an integer"""
        try:
            return int(inaddr, 16)
        except ValueError:
            # inaddr is not a hex string, look for other formats
            if ":" in inaddr:
                bytes = inaddr.split(":")
            elif "-" in inaddr:
                bytes = inaddr.split("-")
            if len(bytes) != 8:
                raise ValueError("Supplied IEEE address does not contain 8 bytes")
            addr = 0
            for i, b in zip(range(8), bytes):
                try:
                    addr += int(b, 16) << (56 - (i * 8))
                except ValueError:
                    raise ValueError("IEEE address contains invalid bytes")
            return addr


async def main():
    cli = CLI()
    args = cli.args
    firmware = None
    cmd = CommandInterface()
    await cmd.open(args.device, args.baud)

    _LOGGER.info("Opening port %s, baud %d", args.device, args.baud)

    if args.bootloader_reset != "none":
        bl = Bootloader(args.device, cmd.transport)

        if args.bootloader_reset or args.host:
            bl.set_mode(args.bootloader_reset, args.host)

        if args.bootloader_active_high or args.bootloader_invert_lines:
            bl.set_options(args.bootloader_active_high, args.bootloader_invert_lines)

        await bl.invoke_bootloader()

        _LOGGER.info("Connecting to target...")
        device = CC26xx(cmd, firmware, args.m33)
        await device.connect()

        if args.write or args.verify:
            _LOGGER.info("Reading data from %s", args.file)
            firmware = FirmwareFile(path=args.file)
            device.set_firmware(firmware)
            # force erase when using segmented writes
            if args.write and firmware.segments:
                args.erase = True

            bl_active = firmware.check_bootloader(
                device.bootloader_address - device.CCFG_BASE - device.CCFG_START
            )
            if not (bl_active or args.force):
                raise Exception(
                    "Bootloader not active in firmware to be flashed.",
                    "Use --force to override.",
                )

    if args.address:
        device.set_flash_start_addr(args.address)

    if args.read:
        await device.read(args.len, args.output)
        _LOGGER.info("Read done")

    if args.erase:
        await device.erase()

    if args.write:
        pbar = tqdm(total=device._firmware.size, unit="B", unit_scale=True)

        if logging.getLogger().getEffectiveLevel() < logging.INFO:
            pbar.disable = True

        await device.flash(
            progress_callback=lambda current, _: pbar.update(MAX_BLOCK_SIZE)
        )
        pbar.close()
        _LOGGER.info("Write done")

    if args.verify:
        _LOGGER.info("Verifying by comparing CRC32 calculations.")
        await device.verify()

    if args.ieee_address:
        ieee_addr = cli.parse_ieee_address(args.ieee_address)
        if await device.set_ieee_address(ieee_addr):
            _LOGGER.info("Set address done")
        else:
            raise CliException("Set address failed")

    if args.disable_bootloader:
        device.disable_bootloader(args.force)

    await cmd.cmdReset()
    await cmd.close()
