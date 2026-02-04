"""Tests for flasher module."""

from unittest.mock import AsyncMock

import pytest

from smlight_cc_flasher.flasher import Flasher


@pytest.fixture
def mock_flasher_deps(mocker):
    """Mock dependencies for Flasher class."""
    mocker.patch("smlight_cc_flasher.flasher.CommandInterface")
    mocker.patch("smlight_cc_flasher.flasher.CC26xx")
    mocker.patch("smlight_cc_flasher.flasher.Bootloader")
    mocker.patch("smlight_cc_flasher.flasher.FirmwareFile")


@pytest.mark.asyncio
async def test_flasher_init(mock_flasher_deps):
    """Test Flasher initialization."""
    flasher = Flasher("/dev/ttyUSB0")
    assert flasher._device == "/dev/ttyUSB0"
    assert flasher.ieee_address is None


@pytest.mark.asyncio
async def test_flasher_flash_with_ieee_override(mocker):
    """Test flashing with explicit IEEE address."""
    # Setup mocks
    mock_cmd = mocker.patch("smlight_cc_flasher.flasher.CommandInterface").return_value
    mock_chip = mocker.patch("smlight_cc_flasher.flasher.CC26xx").return_value
    mocker.patch("smlight_cc_flasher.flasher.Bootloader").return_value
    mocker.patch("smlight_cc_flasher.flasher.FirmwareFile")

    # Setup async methods
    mock_cmd.open = AsyncMock()
    mock_cmd.cmdReset = AsyncMock()
    mock_cmd.close = AsyncMock()
    mock_chip.connect = AsyncMock()
    mock_chip.erase = AsyncMock()
    mock_chip.flash = AsyncMock()
    mock_chip.verify = AsyncMock()
    mock_chip.set_ieee_address = AsyncMock()

    flasher = Flasher("/dev/ttyUSB0")
    # Initialize with specific address
    await flasher.async_init(ieee_address="01:02:03:04:05:06:07:08", buffer=b"dummy")

    await flasher.flash()

    # Should set parsed address
    # 0x0102030405060708
    mock_chip.set_ieee_address.assert_called_once_with(72623859790382856)
    # Ensure chip property was updated as well
    assert mock_chip.ieee_address_secondary == 72623859790382856


@pytest.mark.asyncio
async def test_flasher_flash_restore_ieee(mocker):
    """Test flashing with restoring existing IEEE address."""
    # Setup mocks
    mock_cmd = mocker.patch("smlight_cc_flasher.flasher.CommandInterface").return_value
    mock_chip = mocker.patch("smlight_cc_flasher.flasher.CC26xx").return_value
    mocker.patch("smlight_cc_flasher.flasher.Bootloader").return_value
    mocker.patch("smlight_cc_flasher.flasher.FirmwareFile")

    # Setup async methods
    mock_cmd.open = AsyncMock()
    mock_cmd.cmdReset = AsyncMock()
    mock_cmd.close = AsyncMock()
    mock_chip.connect = AsyncMock()
    mock_chip.erase = AsyncMock()
    mock_chip.flash = AsyncMock()
    mock_chip.verify = AsyncMock()
    mock_chip.set_ieee_address = AsyncMock()

    # Simulate saved address in chip (0xAABBCCDDEEFF0011)
    # 12297829382473089041
    mock_chip.ieee_address_secondary = 0xAABBCCDDEEFF0011

    flasher = Flasher("/dev/ttyUSB0")
    await flasher.async_init(buffer=b"dummy")  # No ieee_address provided

    await flasher.flash()

    mock_chip.set_ieee_address.assert_called_once_with(0xAABBCCDDEEFF0011)


@pytest.mark.asyncio
async def test_flasher_flash_no_ieee(mocker):
    """Test flashing with no IEEE address to set."""
    mock_cmd = mocker.patch("smlight_cc_flasher.flasher.CommandInterface").return_value
    mock_chip = mocker.patch("smlight_cc_flasher.flasher.CC26xx").return_value
    mocker.patch("smlight_cc_flasher.flasher.Bootloader")
    mocker.patch("smlight_cc_flasher.flasher.FirmwareFile")

    mock_cmd.open = AsyncMock()
    mock_cmd.cmdReset = AsyncMock()
    mock_cmd.close = AsyncMock()
    mock_chip.connect = AsyncMock()
    mock_chip.erase = AsyncMock()
    mock_chip.flash = AsyncMock()
    mock_chip.verify = AsyncMock()
    mock_chip.set_ieee_address = AsyncMock()

    # No saved address
    mock_chip.ieee_address_secondary = None

    flasher = Flasher("/dev/ttyUSB0")
    await flasher.async_init(buffer=b"dummy")

    await flasher.flash()

    mock_chip.set_ieee_address.assert_not_called()
