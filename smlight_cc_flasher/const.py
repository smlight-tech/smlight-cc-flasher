# Copyright (c) 2024, SMLIGHT <smartlight.email@gmail.com>
# SPDX-License-Identifier: Apache-2.0

from enum import Enum
from typing import Dict


class COMMAND(Enum):
    PING = 0x20
    DOWNLOAD = 0x21
    GET_STATUS = 0x23
    SEND_DATA = 0x24
    RESET = 0x25
    SECTOR_ERASE = 0x26
    CRC32 = 0x27
    GET_CHIP_ID = 0x28
    MEMORY_READ = 0x2A
    MEMORY_WRITE = 0x2B
    BANK_ERASE = 0x2C
    SET_CCFG = 0x2D
    DOWNLOAD_CRC = 0x2F
    SYNCH = 0x55


class COMMAND_RET(Enum):
    SUCCESS = 0x40
    UNKNOWN_CMD = 0x41
    INVALID_CMD = 0x42
    INVALID_ADR = 0x43
    FLASH_FAIL = 0x44


COMMAND_STRS = {
    member.value: member.name.capitalize().replace("_", " ") for member in COMMAND
}

COMMAND_HAS_DATA: list[int] = [0x23, 0x27, 0x28, 0x2A]

RETURN_CMD_STRS: Dict[int, str] = {
    0x40: "Success",
    0x41: "Unknown command",
    0x42: "Invalid command",
    0x43: "Invalid address",
    0x44: "Flash fail",
}

MAX_BLOCK_SIZE = 252
