# Copyright (c) 2024, SMLIGHT <smartlight.email@gmail.com>
# SPDX-License-Identifier: Apache-2.0

import binascii
from dataclasses import dataclass, field
from io import StringIO
import logging
import struct
from typing import Any, List

from intelhex import IntelHex
import magic

from .exceptions import FwException

_LOGGER = logging.getLogger(__name__)


@dataclass
class Segment:
    start: int
    end: int
    size: int = field(init=False)
    bytes: bytearray

    def __post_init__(self):
        self.size = self.end - self.start

        # remove the last byte, which is the empty
        pop = self.bytes.pop()
        assert pop == 255, "Segment data does not end with 0xFF"

        assert len(self.bytes) == self.size, "Segment size does not match data size"
        self.crc32 = binascii.crc32(bytearray(self.bytes)) & 0xFFFFFFFF
        _LOGGER.debug("Segment: 0x%08x, %d bytes", self.start, self.size)


class FirmwareFile:
    def __init__(self, *, path: str | None = None, buffer: bytearray | None = None):
        """
        Read a firmware file and store its data ready for device programming.

        This class will try to guess the file type using python-magic.

        If python-magic indicates a plain text file, then the file will be
        treated as one of Intel HEX format. In all other cases, the file will
        be treated as a raw binary file.

        In both cases, the file's contents are stored in bytes for subsequent
        usage to program a device or to perform a crc check.

        Parameters:
            path -- A str with the path to the firmware file.

        Attributes:
            bytes: A bytearray with firmware contents ready to send to the
            device
        """
        self._crc32: int | None = None
        self.segments: List[Any] = []
        self.ih: IntelHex
        self.size: int = 0
        file_type = None

        if path:
            file_type = magic.from_file(path, mime=True)
        elif buffer:
            file_type = magic.from_buffer(bytes(buffer), mime=True)
        else:
            return

        if file_type == "text/plain":
            _LOGGER.info("Firmware file: Intel Hex")

            fobj = StringIO(bytearray(buffer).decode()) if buffer else path
            self.read_hex(fobj)
        elif (
            file_type == "application/octet-stream"
            or file_type == "application/x-dosexec"
        ):
            _LOGGER.info("Firmware file: Raw Binary")
            self._read_bin(path)
        else:
            error_str = f"Could not determine firmware type, {file_type}"
            raise FwException(error_str)

    def read_hex(self, path: str | StringIO):
        self.ih = IntelHex(path)
        self._process_hex()

    async def from_buffer(self, buffer):
        blob = await buffer.text()
        fobj = StringIO(blob)
        self.ih = IntelHex(fobj)
        self._process_hex()

    def _process_hex(self):
        for segment in self.ih.segments(min_gap=2048):
            data = bytearray(self.ih.tobinarray(*segment))
            self.segments.append(Segment(segment[0], segment[1], data))
            self.size += len(data)

    def _read_bin(self, source: str | bytearray):
        if isinstance(source, str):
            with open(source, "rb") as f:
                self.bytes = bytearray(f.read())
        else:
            self.bytes = source
        self.size = len(self.bytes)

    def crc32(self):
        """
        Return the crc32 checksum of the firmware image

        Return:
            The firmware's CRC32, ready for comparison with the CRC
            returned by the ROM bootloader's COMMAND_CRC32
        """
        if self._crc32 is None:
            self._crc32 = binascii.crc32(bytearray(self.bytes)) & 0xFFFFFFFF

        return self._crc32

    def check_bootloader(self, offset: int) -> bool:
        """
        Check if the settings of bootloader in firmware image

        Parameters:
            offset -- The offset to the BL_CONFIG field in the CCFG area

        Return:
            True if the bootloader backdoor is enabled, False otherwise
        """
        data = self.segments[-1].bytes[offset : offset + 4]
        _LOGGER.debug("BL_CONFIG: 0x%08x" % struct.unpack("<I", data)[0])

        bl_enabled = data[0] == 0xC5 and data[3] == 0xC5
        bl_pin = data[1]
        active_low = not (data[2] & 0x01)

        if bl_enabled:
            _LOGGER.info("BL_PIN: %d, Active Low: %s", bl_pin, active_low)
        return bl_enabled
