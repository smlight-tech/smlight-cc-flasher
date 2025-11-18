# Copyright (c) 2024, SMLIGHT <smartlight.email@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import asyncio
from collections.abc import AsyncGenerator
import logging
import re
import socket
import struct
from typing import Any

import serial_asyncio

from .const import (
    COMMAND,
    COMMAND_HAS_DATA,
    COMMAND_RET,
    COMMAND_STRS,
    MAX_BLOCK_SIZE,
    RETURN_CMD_STRS,
)
from .exceptions import CmdException
from .gpio import GpioConfig, gpioResets

_LOGGER = logging.getLogger(__name__)


class PinSetter:
    def __init__(self, instance: Any, attr_name: str) -> None:
        self.instance = instance
        self.attr_name = attr_name
        self._webserial = hasattr(instance, "webserial")

    async def __call__(self, value: bool | None = None) -> bool | None:
        if not self._webserial:
            if value is not None:
                setattr(self.instance, self.attr_name, value)
            return bool(getattr(self.instance, self.attr_name))
        else:
            if value is not None:
                _LOGGER.info("_%s", self.attr_name)
                setter = getattr(self.instance, f"set_{self.attr_name}")
                await setter(value)
                _LOGGER.info(
                    "%s: %s",
                    self.attr_name,
                    getattr(self.instance, f"_{self.attr_name}"),
                )
            return None

    def get_instance(self) -> Any:
        return self.instance


class Bootloader:
    """
    Automatically invoke the bootloader on a device.
    Use DTR/RTS to reset the device and enter the bootloader.
    For SLZB-06 use the network API to invoke the bootloader.
    For devices with GPIO controls, use GPIO patterns to enter bootloader.
    """

    CONNECT_TIMEOUT = 1

    def __init__(self, device: str, transport: Any) -> None:
        self._device = device
        self._serial = transport.serial
        self._dtr_active_high = False
        self._inverted = False
        self._generic = True
        self._generic2 = False
        self._smlight_net = False
        self._gpio = False
        self._gpio_config: GpioConfig | None = None
        self._host: str
        match = re.match(r"socket://([^:]+):([0-9]+)", device)
        if match:
            self._host = match.group(1)
            self._smlight_net = True

    def set_mode(self, mode: str, host: str | None = None) -> None:
        if host and not hasattr(self, "_host"):
            self._host = host
            self._smlight_net = True

        if mode != "generic":
            self._generic = False

        match mode:
            case "generic":
                pass
            case "generic2":
                self._generic2 = True
            case "network":
                self._smlight_net = True
            case "none":
                pass
            case _:
                # Assume it's a GPIO config name
                self.set_gpio_config(mode)
                self._gpio = True
        return

    def set_gpio_config(self, config_name: str) -> None:
        """Set the GPIO configuration to use."""
        if config_name not in gpioResets:
            raise ValueError(
                f"GPIO config '{config_name}' not found. "
                f"Available configs: {', '.join(gpioResets.keys())}"
            )
        self._gpio_config = gpioResets[config_name]

    def set_options(self, dtr_active_high: bool, inverted: bool) -> None:
        self._dtr_active_high = dtr_active_high
        self._inverted = inverted

    async def invoke_bootloader(self) -> None:
        if self._smlight_net or "socket" in self._device:
            await self.invoke_smlight_net(self._host)
        elif self._gpio:
            await self.invoke_gpio()
        else:
            # Set up serial pins for DTR/RTS control
            if self._inverted:
                self.set_bootloader_pin = PinSetter(self._serial, "rts")
                self.set_reset_pin = PinSetter(self._serial, "dtr")
            else:
                self.set_bootloader_pin = PinSetter(self._serial, "dtr")
                self.set_reset_pin = PinSetter(self._serial, "rts")

            if self._generic2:
                await self.invoke_generic2()
            else:
                await self.invoke_generic()

        await asyncio.sleep(0.1)

    async def invoke_generic2(self) -> None:
        _LOGGER.info("Activating generic2 BSL")
        # Dongles that use Flipflop logic for bsl.
        # Connection between RTS DTR and reset and IO15:
        # DTR  RTS  |  RST  IO15
        # 1     1   |   1    1
        # 0     0   |   1    1
        # 1     0   |   0    1
        # 0     1   |   1    0
        await self.set_bootloader_pin(False)
        await self.set_reset_pin(True)
        await asyncio.sleep(0.1)
        await self.set_bootloader_pin(True)
        await self.set_reset_pin(False)
        await asyncio.sleep(0.2)
        await self.set_bootloader_pin(False)

    async def invoke_generic(self) -> None:
        await self.set_bootloader_pin(True if not self._dtr_active_high else False)
        await self.set_reset_pin(True)
        await self.set_reset_pin(False)
        await asyncio.sleep(0.2)
        await self.set_bootloader_pin(False if not self._dtr_active_high else True)
        # await asyncio.sleep(0.5)

    async def invoke_gpio(self) -> None:
        """Invoke bootloader using GPIO pattern."""
        from .gpio import send_gpio_pattern

        if self._gpio_config is None:
            raise ValueError("GPIO config not set. Call set_gpio_config() first.")

        _LOGGER.info("Activating BSL via GPIO on %s", self._gpio_config.chip)
        await send_gpio_pattern(self._gpio_config.chip, self._gpio_config.patterns)

    async def invoke_smlight_net(self, host: str) -> bool:
        from pysmlight.const import Commands
        from pysmlight.web import Api2

        _LOGGER.info("Activating SMLIGHT BSL via network")
        async with Api2(host) as client:
            if await client.check_auth_needed():
                return False

            return bool(await client.set_cmd(Commands.CMD_ZB_BSL))  # type: ignore[attr-defined]


class CommandInterface:
    ACK = b"\x00\xcc"
    NACK = b"\x00\x33"

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    webserial: bool

    async def open(self, aport: str | None = None, abaudrate: int = 500000) -> None:
        self.reader, self.writer = await serial_asyncio.open_serial_connection(
            url=aport,
            baudrate=abaudrate,  # , timeout=1
        )
        self.webserial = hasattr(self.writer.transport.serial, "webserial")  # type: ignore[attr-defined]
        _LOGGER.info("Opened port %s, baud %d", aport, abaudrate)

        sock = self.writer.transport.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    async def close(self) -> None:
        _LOGGER.info("Closing port")

        self.writer.close()
        await self.writer.wait_closed()

    @property
    def transport(self) -> Any:
        return self.writer.transport

    async def _wait_for_ack(self, cmd: COMMAND, timeout: int = 1) -> bool:
        got = bytearray()
        info = f"{COMMAND_STRS[cmd.value]} (0x{cmd.value:02X})"
        while True:
            try:
                got += await asyncio.wait_for(self.reader.read(1), timeout)
            except asyncio.exceptions.TimeoutError as e:
                if cmd != COMMAND.SYNCH:
                    raise CmdException("Timeout waiting for ACK/NACK after '%s'", info)
                raise e

            if CommandInterface.ACK in got:
                _LOGGER.debug("Got %d additional bytes before ACK/NACK", (len(got) - 2))
                return True
            elif CommandInterface.NACK in got:
                _LOGGER.debug("Target replied with a NACK during %s", info)
                return False

    def _encode_addr(self, addr: int) -> bytes:
        """encode 32-bit integer as 4 bytes"""
        return struct.pack(">I", addr)

    def _decode_addr(self, addr: bytes) -> int:
        """decode bytes as 32-bit integer"""
        result: tuple[int] = struct.unpack(">I", addr)
        return result[0]

    async def _write(self, data: int | bytes | bytearray) -> None:
        if isinstance(data, int):
            assert data < 256
            data = bytes([data])

        length = len(data)
        self.writer.write(data)
        await self.writer.drain()

        buffer_size = 0
        if not self.webserial:
            buffer_size = self.writer.transport.get_write_buffer_size()
        assert isinstance(data, bytes | bytearray), "Bad data type"
        _LOGGER.debug("*** Wrote %d/%d bytes", buffer_size, length)

    async def _sendCmd(
        self,
        cmd: COMMAND,
        *,
        addr: int | None = None,
        size: int | None = None,
        data: bytes | bytearray | None = None,
        extra: bytes | bytearray | None = None,
    ) -> None:
        cmd_bytes = bytes([cmd.value])

        packet = cmd_bytes

        if addr is not None:
            packet += self._encode_addr(addr)

        if size is not None:
            packet += self._encode_addr(size)

        if extra is not None:
            packet += extra

        if data:
            assert len(data) <= 252
            packet += data

        crc = bytes([sum(packet) & 0xFF])
        packet = crc + packet
        if cmd_bytes != b"\x55":
            packet = bytes([len(packet) + 1]) + packet

        await self._write(packet)

    async def _processCmd(
        self,
        cmd: COMMAND,
        *,
        addr: int | None = None,
        size: int | None = None,
        data: bytes | bytearray | None = None,
        extra: bytes | bytearray | None = None,
    ) -> bool | int | bytes:
        _LOGGER.debug("*** %s command (0x%02x)", COMMAND_STRS[cmd.value], cmd.value)
        await self._sendCmd(cmd, addr=addr, size=size, data=data, extra=extra)

        if await self._wait_for_ack(cmd):
            if cmd == COMMAND.RESET or cmd == COMMAND.SYNCH:
                return True

            ret_data = None
            if cmd.value in COMMAND_HAS_DATA:
                ret_data = await self.receivePacket()
                if cmd == COMMAND.GET_STATUS:
                    return ret_data

            ret = await self.checkLastCmd()

            if ret and ret_data:
                return ret_data
            return ret
        return False

    async def receivePacket(self) -> int | bytes:
        hdr = await self.reader.readexactly(2)
        size, chks = hdr
        data = await self.reader.readexactly(size - 2)

        _LOGGER.debug("*** received %x bytes", size)
        if chks == sum(data) & 0xFF:
            await self._write(CommandInterface.ACK)
            return data if len(data) > 1 else data[0]
        else:
            await self._write(CommandInterface.NACK)
            raise CmdException("Received packet checksum error")

    async def sendSynch(self) -> bool:
        cmd = COMMAND.SYNCH

        if not self.webserial:
            self.writer.transport.flush()  # type: ignore[attr-defined]

        return bool(await self._processCmd(cmd))

    async def checkLastCmd(self) -> bool:
        status = await self.cmdGetStatus()
        if not status:
            raise CmdException("No response from target on status request.")

        status_int = status[0] if isinstance(status, bytes) else int(status)

        if status_int == COMMAND_RET.SUCCESS.value:
            return True
        else:
            status_str = RETURN_CMD_STRS.get(status_int, None)
            if status_str is None:
                _LOGGER.error("Warning: unrecognized status returned 0x%x", status_int)
            else:
                _LOGGER.error("Target returned: 0x%x, %s", status_int, status_str)
            return False

    async def cmdPing(self) -> bool:
        cmd = COMMAND.PING

        return bool(await self._processCmd(cmd))

    async def cmdReset(self) -> bool:
        cmd = COMMAND.RESET

        return bool(await self._processCmd(cmd))

    async def cmdGetChipId(self) -> int:
        cmd = COMMAND.GET_CHIP_ID

        version = await self._processCmd(cmd)

        if version:
            if isinstance(version, int):
                return version
            assert len(version) == 4, f"Unreasonable chip id: {repr(version)}"
            _LOGGER.debug("Version 0x%s", "".join(f"{v:02X}" for v in version))
            chip_id = (version[2] << 8) | version[3]
            return chip_id
        else:
            raise CmdException("GetChipID (0x28) failed")

    async def cmdGetStatus(self) -> bool | int | bytes:
        cmd = COMMAND.GET_STATUS

        return await self._processCmd(cmd)

    async def cmdEraseSector(self, addr: int) -> bool:
        """cc26xx only"""
        cmd = COMMAND.SECTOR_ERASE

        return bool(await self._processCmd(cmd, addr=addr))

    async def cmdBankErase(self) -> bool:
        cmd = COMMAND.BANK_ERASE

        return bool(await self._processCmd(cmd))

    async def cmdCRC32(self, addr: int, size: int) -> int | None:
        cmd = COMMAND.CRC32
        extra = self._encode_addr(0x00000000)
        crc = await self._processCmd(cmd, addr=addr, size=size, extra=extra)
        if crc:
            assert isinstance(crc, bytes), "CRC32 command should return bytes"
            return self._decode_addr(crc)
        return None

    async def cmdCRC32Segment(self, firmware: Any) -> list[int | None]:
        crc32 = []
        for segment in firmware.segments:
            crc32.append(await self.cmdCRC32(segment.start, segment.size))
        return crc32

    async def cmdDownload(self, addr: int, size: int) -> bool:
        cmd = COMMAND.DOWNLOAD

        if (size % 4) != 0:  # check for invalid data lengths
            raise CmdException(
                "Invalid data size: %d. Size must be a multiple of 4.", size
            )

        return bool(await self._processCmd(cmd, addr=addr, size=size))

    async def cmdDownloadCRC32(self, addr: int, size: int, crc: int) -> bool:
        cmd = COMMAND.DOWNLOAD_CRC

        if (size % 4) != 0:  # check for invalid data lengths
            raise CmdException(
                "Invalid data size: %d. Size must be a multiple of 4.", size
            )

        return bool(
            await self._processCmd(
                cmd, addr=addr, size=size, extra=self._encode_addr(crc)
            )
        )

    async def cmdSendData(self, data: bytes | bytearray) -> bool:
        cmd = COMMAND.SEND_DATA
        # data = bytearray(data)
        assert isinstance(data, bytes | bytearray), "Bad data type"
        return bool(await self._processCmd(cmd, data=data))

    async def cmdMemRead(self, addr: int) -> int | bytes:
        cmd = COMMAND.MEMORY_READ
        data = await self._processCmd(cmd, addr=addr, extra=b"\x01\x01")
        return data

    async def cmdMemWrite(self, addr: int, data: bytes | bytearray, width: int) -> bool:
        """cc26xx"""
        if width != len(data):
            raise ValueError("width does not match len(data)")
        if width != 1 and width != 4:
            raise ValueError("width must be 1 or 4")

        cmd = COMMAND.MEMORY_WRITE

        return bool(await self._processCmd(cmd, addr=addr, data=data, extra=b"\x01"))

    async def arange(
        self, start: int, stop: int, step: int
    ) -> AsyncGenerator[int, None]:
        for i in range(start, stop, step):
            yield i
            await asyncio.sleep(0.0)

    async def writeMemory(
        self,
        addr: int,
        data: bytes | bytearray,
        *,
        progress_callback: Any = None,
    ) -> bool:
        length = len(data)
        # amount of data bytes transferred per packet (theory: max 252 + 3)
        pkt_size = MAX_BLOCK_SIZE
        empty_packet = bytearray((0xFF,) * pkt_size)

        offset = 0
        addr_set = False
        last_result = False

        data_slices = (
            data[i : i + pkt_size] async for i in self.arange(0, len(data), pkt_size)
        )

        if progress_callback is not None:
            progress_callback(0, len(data))

        async for packet in data_slices:
            if packet != empty_packet:
                if not addr_set:
                    # set starting address if not set
                    await self.cmdDownload(addr + offset, length - offset)
                    addr_set = True
                _LOGGER.debug(
                    f"Writing {pkt_size} bytes starting at address"
                    f"0x{addr + offset:08X}"
                )

                last_result = await self.cmdSendData(packet)
                if not last_result:
                    raise CmdException("Write memory failed")

                if progress_callback is not None:
                    progress_callback(offset, length)
            else:
                addr_set = False

            offset += pkt_size

        return last_result
