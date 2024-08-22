# Copyright (c) 2024, SMLIGHT <smartlight.email@gmail.com>
# SPDX-License-Identifier: Apache-2.0

from asyncio.exceptions import TimeoutError
import logging
import math
import struct

from .command import CommandInterface
from .exceptions import DeviceException
from .firmware import FirmwareFile

_LOGGER = logging.getLogger(__name__)


class Chip:
    def __init__(self, command_interface, m33=False):
        self.command_interface = command_interface

        self.flash_start_addr = 0x00000000
        self.bootloader_dis_val = 0xFFFFFFC5
        self.page_size = 2048
        self.m33 = m33

    def page_align_up(self, value):
        return int(math.ceil(value / self.page_size) * self.page_size)

    def page_align_down(self, value):
        return int(math.floor(value / self.page_size) * self.page_size)

    def page_to_addr(self, pages):
        addresses = []
        for page in pages:
            addresses.append(int(self.flash_start_addr) + int(page) * self.page_size)
        return addresses

    def set_flash_start_addr(self, addr):
        self.flash_start_addr = addr

    def disable_bootloader(self, force):
        if not force:
            error_str = (
                "Disabling the bootloader will prevent you from "
                "using this script until you re-enable the "
                "bootloader using JTAG. Use --force if sure.",
            )
            _LOGGER.warning(error_str)
            raise DeviceException("Aborted.")

        pattern = struct.pack("<L", self.bootloader_dis_val)

        if self.command_interface.writeMemory(self.bootloader_address, pattern):
            _LOGGER.info("Set bootloader closed done")
        else:
            raise DeviceException("Set bootloader closed failed")


class CC26xx(Chip):
    # Class constants
    PROTO_MASK_BLE = 0x01
    PROTO_MASK_IEEE = 0x04
    PROTO_MASK_BOTH = 0x05

    def __init__(
        self,
        command_interface: CommandInterface,
        firmware: FirmwareFile | None = None,
        m33: bool = False,
    ):
        super().__init__(command_interface, m33)
        if firmware:
            self._firmware: FirmwareFile = firmware

        if self.m33:
            self.FCFG_BASE = 0x50000800  # P10
            self.CCFG_BASE = 0x50000000
            self.CCFG_OFFSET = 0x00
            self.CCFG_START = 0x00
            self.page_size = 2048
            self.FLASH_BASE = 0x58030000
        else:
            self.FCFG_BASE = 0x50001000
            self.CCFG_BASE = 0x50003000
            self.page_size = 4096
            self.CCFG_OFFSET = 0x1FB0
            self.CCFG_START = 0x1FA8
            self.FLASH_BASE = 0x40030000

    def set_firmware(self, file: FirmwareFile):
        self._firmware = file

    async def async_init(self):
        fcfg_user_id_offset = 0x294
        fcfg_icepick_id_offset = 0x318
        flash_size_offset = 0x2C
        ieee_address_primary_offset = 0x2F0  # FCFG1
        ieee_address_secondary_offset = 0x18  # CCFG
        bl_config_offset = 0x28
        self.misc_conf_1_offset = 0xA0  # FCFG1

        # Determine CC13xx vs CC26xx via ICEPICK_DEVICE_ID::WAFER_ID and store
        # PG revision
        device_id = await self.command_interface.cmdMemRead(
            self.FCFG_BASE + fcfg_icepick_id_offset
        )
        wafer_id = (
            ((device_id[3] & 0x0F) << 16) + (device_id[2] << 8) + (device_id[1] & 0xF0)
        ) >> 4
        pg_rev = (device_id[3] & 0xF0) >> 4

        # Read FCFG1_USER_ID to get the package and supported protocols
        user_id = await self.command_interface.cmdMemRead(
            self.FCFG_BASE + fcfg_user_id_offset
        )
        package = {
            0x00: "4x4mm",
            0x01: "5x5mm",
            0x02: "7x7mm",
            0x03: "Wafer",
            0x04: "2.7x2.7",
            0x05: "7x7mm Q1",
        }.get(user_id[2] & 0x07, "Unknown")

        protocols = user_id[1] >> 4

        # We can now detect the exact device
        _LOGGER.info(
            "pg_rev = {:0x}, protocols = {:0x}, wafer_id = 0x{:04x}".format(
                pg_rev, protocols, wafer_id
            ),
        )

        if wafer_id == 0xB99A:  # CC26x0
            chip = await self._identify_cc26xx(pg_rev, protocols)
        elif wafer_id == 0xB9BE:  # CC13x0
            chip = await self._identify_cc13xx(pg_rev, protocols)
        elif wafer_id == 0xBB41:  # CC13x2/CC26x2
            chip = await self._identify_cc13xx(pg_rev, protocols)
            self.page_size = 8192
        elif wafer_id == 0xBB77:  # CC13x2x7/CC26x2x7
            chip = await self._identify_cc13xx(pg_rev, protocols)
            self.page_size = 8192
        elif wafer_id == 0xBB78:  # CC13x4/CC27x4P
            chip = await self._identify_cc2674(pg_rev)
            self.page_size = 2048
        else:
            raise DeviceException("Unknown wafer_id: 0x%04x", wafer_id)

        flash_size = await self.command_interface.cmdMemRead(
            self.FLASH_BASE + flash_size_offset
        )
        if self.m33:
            self.size = (
                (((flash_size[1] & 0x03) << 1) + ((flash_size[0] & 0x80) >> 7))
                * 256
                * 1024
            )
        else:
            self.size = flash_size[0] * self.page_size

        self.bootloader_address = self.CCFG_BASE + self.CCFG_OFFSET + bl_config_offset
        self.addr_ieee_address_secondary = (
            self.CCFG_BASE + self.CCFG_OFFSET + ieee_address_secondary_offset
        )

        # Primary IEEE address. Stored with the MSB at the high address
        ieee_addr = await self.command_interface.cmdMemRead(
            self.FCFG_BASE + ieee_address_primary_offset + 4
        )
        ieee_addr = ieee_addr[::-1]
        ieee_addr2 = await self.command_interface.cmdMemRead(
            self.FCFG_BASE + ieee_address_primary_offset
        )
        ieee_addr += ieee_addr2[::-1]

        _LOGGER.info(
            f"{chip} ({package}): {self.size >> 10}KB Flash, "
            f"CCFG.BL_CONFIG at 0x{self.bootloader_address:08X}"
        )
        _LOGGER.info(
            "Primary IEEE Address: %s", ":".join(f"{x:02x}" for x in ieee_addr)
        )

    async def _identify_cc26xx(self, pg, protocols):
        chips_dict = {
            CC26xx.PROTO_MASK_IEEE: "CC2630",
            CC26xx.PROTO_MASK_BLE: "CC2640",
            CC26xx.PROTO_MASK_BOTH: "CC2650",
        }

        chip_str = chips_dict.get(protocols & CC26xx.PROTO_MASK_BOTH, "Unknown")

        if pg == 1:
            pg_str = "PG1.0"
        elif pg == 3:
            pg_str = "PG2.0"
        elif pg == 7:
            pg_str = "PG2.1"
        elif pg == 8 or pg == 0x0B:
            # CC26x0 PG2.2+ or CC26x0R2
            rev_minor = await self.command_interface.cmdMemRead(
                self.FCFG_BASE + self.misc_conf_1_offset
            )
            rev_minor = rev_minor[0]
            if rev_minor == 0xFF:
                rev_minor = 0x00

            if pg == 8:
                # CC26x0
                pg_str = f"PG2.{(2 + rev_minor):d}"
            elif pg == 0x0B:
                # HW revision R2, update Chip name
                chip_str += "R2"
                pg_str = "PG%d.%d" % (1 + (rev_minor // 10), rev_minor % 10)

        return f"{chip_str} {pg_str}"

    async def _identify_cc2674(self, pg):
        chip_str = "CC2674"
        if pg == 0:
            pg_str = "PG1"
        elif pg == 1:
            pg_str = "PG2"

        rev_minor = await self.command_interface.cmdMemRead(
            self.FCFG_BASE + self.misc_conf_1_offset
        )
        rev_minor = rev_minor[0]
        if rev_minor == 0xFF:
            rev_minor = 0x00

        pg_str = f"{pg_str}.{rev_minor:d}"

        return f"{chip_str} {pg_str}"

    async def _identify_cc13xx(self, pg, protocols):
        chip_str = "CC131x"
        if protocols & CC26xx.PROTO_MASK_IEEE == CC26xx.PROTO_MASK_IEEE:
            chip_str = "CC135x"

        if pg == 0:
            pg_str = "PG1.0"
        if pg == 1:
            pg_str = "PG1.1"
        elif pg == 2 or pg == 3:
            rev_minor = await self.command_interface.cmdMemRead(
                self.FCFG_BASE + self.misc_conf_1_offset
            )
            rev_minor = rev_minor[0]
            if rev_minor == 0xFF:
                rev_minor = 0x00
            pg_str = f"PG2.{rev_minor:d}"
        else:
            pg_str = "PG1.0"

        return f"{chip_str} {pg_str}"

    async def crc(self, address, size):
        return await self.command_interface.cmdCRC32(address, size)

    async def connect(self):
        try:
            await self.command_interface.sendSynch()
        except TimeoutError:
            raise DeviceException(
                "Can't connect to target. Ensure boot loader "
                "is started. (no answer on synch sequence)"
            )
        await self.async_init()

    async def erase(self):
        ret = await self.erase_bank()
        if ret and self.m33:
            ret = await self.erase_ccfg()
        if ret:
            _LOGGER.info("Erase done")
        else:
            raise DeviceException("Erase failed")

    async def erase_bank(self):
        _LOGGER.info("Erasing all main bank flash sectors")
        return await self.command_interface.cmdBankErase()

    async def erase_ccfg(self):
        _LOGGER.info("Erasing CCFG")
        return await self.command_interface.cmdEraseSector(self.CCFG_BASE)

    async def read_memory(self, addr):
        return await self.command_interface.cmdMemRead(addr)

    async def set_ieee_address(self, ieee_addr):
        formatted_addr = f"{':'.join(f'{b:02x}' for b in struct.pack('>Q', ieee_addr))}"
        _LOGGER.info("Setting IEEE address to %s", formatted_addr)
        ieee_addr_bytes = struct.pack("<Q", ieee_addr)

        return await self.command_interface.writeMemory(
            self.addr_ieee_address_secondary, ieee_addr_bytes
        )

    async def flash(self, progress_callback=None):
        if self._firmware.segments:
            for segment in self._firmware.segments:
                msg = (
                    f"Writing {segment.size} bytes starting at address "
                    f"0x{segment.start:08X}"
                )
                _LOGGER.debug(msg)

                await self.command_interface.writeMemory(
                    segment.start, segment.bytes, progress_callback=progress_callback
                )

        else:
            await self.command_interface.writeMemory(
                self.flash_start_addr,
                self._firmware.bytes,
                progress_callback=progress_callback,
            )

    async def read(self, length, output):
        # Round up to a 4-byte boundary
        length = (length + 3) & ~0x03

        _LOGGER.info(
            f"Reading {length} bytes starting at address 0x{self.flash_start_addr:x}",
        )
        with open(output, "wb") as f:
            for i in range(0, length >> 2):
                # reading 4 bytes at a time
                rdata = await self.read_memory(self.flash_start_addr + (i * 4))
                _LOGGER.debug(
                    " 0x%x: 0x%02x%02x%02x%02x"
                    % (
                        self.flash_start_addr + (i * 4),
                        rdata[0],
                        rdata[1],
                        rdata[2],
                        rdata[3],
                    )
                )
                f.write(rdata)

    async def verify(self):
        if self._firmware.segments:
            crc_list = await self.command_interface.cmdCRC32Segment(self._firmware)

            for idx in range(len(crc_list)):
                if crc_list[idx] == self._firmware.segments[idx].crc32:
                    _LOGGER.info(
                        f"Verified Segment {idx:d} (match: 0x{crc_list[idx]:08x})"
                    )
                else:
                    await self.command_interface.cmdReset()
                    raise Exception(
                        f"NO CRC32 match segment {idx:d}: Local = 0x{crc_list[idx]:x}, "
                        f"Target = 0x{self._firmware.segments[idx].crc32:x}"
                    )
        else:
            crc_local = self._firmware.crc32()
            crc_target = self.crc(self.flash_start_addr, len(self._firmware.bytes))

            if crc_local == crc_target:
                _LOGGER.info("Verified (match: 0x%08x)", crc_local)
            else:
                await self.command_interface.cmdReset()
                raise Exception(
                    "NO CRC32 match: Local = 0x{:x}, "
                    "Target = 0x{:x}".format(crc_local, crc_target)
                )
