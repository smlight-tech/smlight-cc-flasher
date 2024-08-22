# Copyright (c) 2024, SMLIGHT <smartlight.email@gmail.com>
# SPDX-License-Identifier: Apache-2.0

""" Flasher class for api use via cc-web-tools or HA"""

import logging
from typing import Any, Callable, Optional

from .command import Bootloader, CommandInterface
from .device import CC26xx
from .firmware import FirmwareFile

LOG_LEVELS = [logging.INFO, logging.DEBUG]
VERBOSE = True
_LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=LOG_LEVELS[min(len(LOG_LEVELS) - 1, VERBOSE)])


class Flasher:
    def __init__(
        self,
        device: str,
        *,
        baudrate: int = 500000,
        m33: bool = False,
        bsl2: bool = False,
    ):
        self._device = device
        self._baudrate = baudrate
        self._m33 = m33
        self.bsl2 = bsl2
        self.command_interface = CommandInterface()
        self.firmware: FirmwareFile | None = None

    async def async_init(self, file: str | None = None):
        if file is not None:
            self.firmware = FirmwareFile(path=file)
        self.chip = CC26xx(self.command_interface, self.firmware, self._m33)
        await self.command_interface.open(self._device, self._baudrate)
        self.bootloader = Bootloader(self._device, self.command_interface.transport)
        if self.bsl2:
            self.bootloader.set_mode("generic2")

    async def connect(self):
        _LOGGER.debug("Activate bootloader")
        await self.bootloader.invoke_bootloader()
        await self.chip.connect()

    def set_firmware(self, file):
        self.chip.set_firmware(file)

    async def flash(
        self, progress_callback: Optional[Callable[[int, int], Any]] = None
    ):
        await self.chip.erase()
        await self.chip.flash(progress_callback=progress_callback)
        await self.chip.verify()
        await self.command_interface.cmdReset()
        await self.command_interface.close()
