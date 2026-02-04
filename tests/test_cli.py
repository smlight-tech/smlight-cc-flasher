"""Tests for cli module."""

from unittest.mock import AsyncMock

import pytest

from smlight_cc_flasher.cli import main


@pytest.mark.asyncio
async def test_cli_ieee_override(mocker):
    """Test CLI with explicit IEEE address."""
    mocker.patch(
        "sys.argv",
        [
            "prog",
            "-d",
            "/dev/ttyUSB0",
            "-w",
            "-i",
            "01:02:03:04:05:06:07:08",
            "-f",
            "firmware.bin",
        ],
    )

    # Mock dependencies
    mock_cmd_cls = mocker.patch("smlight_cc_flasher.cli.CommandInterface")
    mock_cmd_inst = mock_cmd_cls.return_value
    mock_cmd_inst.open = AsyncMock()
    mock_cmd_inst.cmdReset = AsyncMock()
    mock_cmd_inst.close = AsyncMock()
    mock_cmd_inst.transport = mocker.Mock()

    mock_boot_cls = mocker.patch("smlight_cc_flasher.cli.Bootloader")
    mock_boot_inst = mock_boot_cls.return_value
    mock_boot_inst.invoke_bootloader = AsyncMock()

    mock_device_cls = mocker.patch("smlight_cc_flasher.cli.CC26xx")
    mock_device = mock_device_cls.return_value
    mock_device.connect = AsyncMock()
    mock_device.flash = AsyncMock()
    mock_device.set_ieee_address = AsyncMock(return_value=True)
    # Ensure erase is present since args.erase might be triggered
    mock_device.erase = AsyncMock()
    # Simulate some initial value that should be overwritten
    mock_device.ieee_address_secondary = 0xFFFFFFFFFFFFFFFF

    mock_fw_cls = mocker.patch("smlight_cc_flasher.cli.FirmwareFile")
    mock_fw_inst = mock_fw_cls.return_value
    # segments is accessed. If it returns truthy, checks loop
    mock_fw_inst.segments = []
    mock_fw_inst.check_bootloader.return_value = True
    # size is accessed for tqdm
    mock_fw_inst.size = 100

    mocker.patch("smlight_cc_flasher.cli.tqdm")

    await main()

    # Logic in CLI:
    mock_device.set_ieee_address.assert_called_once_with(72623859790382856)


@pytest.mark.asyncio
async def test_cli_ieee_restore(mocker):
    """Test CLI restoring IEEE address when not provided but found on device.
    and we are WRITING (-w).
    """
    mocker.patch("sys.argv", ["prog", "-d", "/dev/ttyUSB0", "-w", "-f", "firmware.bin"])

    mock_cmd_cls = mocker.patch("smlight_cc_flasher.cli.CommandInterface")
    mock_cmd_inst = mock_cmd_cls.return_value
    mock_cmd_inst.open = AsyncMock()
    mock_cmd_inst.cmdReset = AsyncMock()
    mock_cmd_inst.close = AsyncMock()
    mock_cmd_inst.transport = mocker.Mock()

    mock_boot_cls = mocker.patch("smlight_cc_flasher.cli.Bootloader")
    mock_boot_inst = mock_boot_cls.return_value
    mock_boot_inst.invoke_bootloader = AsyncMock()

    mock_device_cls = mocker.patch("smlight_cc_flasher.cli.CC26xx")
    mock_device = mock_device_cls.return_value
    mock_device.connect = AsyncMock()
    mock_device.flash = AsyncMock()
    mock_device.set_ieee_address = AsyncMock(return_value=True)
    mock_device.erase = AsyncMock()

    mock_fw_cls = mocker.patch("smlight_cc_flasher.cli.FirmwareFile")
    mock_fw_inst = mock_fw_cls.return_value
    mock_fw_inst.segments = []
    mock_fw_inst.check_bootloader.return_value = True
    mock_fw_inst.size = 100

    mocker.patch("smlight_cc_flasher.cli.tqdm")

    # Simulate address found on device
    mock_device.ieee_address_secondary = 0xAABBCCDDEEFF0011

    await main()

    mock_device.set_ieee_address.assert_called_once_with(0xAABBCCDDEEFF0011)


@pytest.mark.asyncio
async def test_cli_no_ieee_action_on_read(mocker):
    """Test CLI does NOT write IEEE address on read operation even if known."""
    mocker.patch(
        "sys.argv", ["prog", "-d", "/dev/ttyUSB0", "-r", "-l", "100", "-o", "dump.bin"]
    )

    mock_cmd_cls = mocker.patch("smlight_cc_flasher.cli.CommandInterface")
    mock_cmd_inst = mock_cmd_cls.return_value
    mock_cmd_inst.open = AsyncMock()
    mock_cmd_inst.cmdReset = AsyncMock()
    mock_cmd_inst.close = AsyncMock()
    mock_cmd_inst.transport = mocker.Mock()

    mock_boot_cls = mocker.patch("smlight_cc_flasher.cli.Bootloader")
    mock_boot_inst = mock_boot_cls.return_value
    mock_boot_inst.invoke_bootloader = AsyncMock()

    mock_device_cls = mocker.patch("smlight_cc_flasher.cli.CC26xx")
    mock_device = mock_device_cls.return_value
    mock_device.connect = AsyncMock()
    mock_device.read = AsyncMock()
    mock_device.set_ieee_address = AsyncMock(return_value=True)

    # Simulate address found on device
    mock_device.ieee_address_secondary = 0xAABBCCDDEEFF0011

    await main()

    # Should NOT call set_ieee_address because we are not writing and not specifying address
    mock_device.set_ieee_address.assert_not_called()
