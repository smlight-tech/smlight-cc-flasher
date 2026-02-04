"""Tests for command module."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from smlight_cc_flasher.command import Bootloader, CommandInterface, PinSetter
from smlight_cc_flasher.const import COMMAND
from smlight_cc_flasher.exceptions import CmdException


class TestPinSetter:
    """Tests for PinSetter class."""

    def test_pinsetter_initialization(self):
        """Test PinSetter initialization without webserial."""
        instance = Mock(spec=[])  # No webserial attribute
        setter = PinSetter(instance, "test_attr")

        assert setter.instance == instance
        assert setter.attr_name == "test_attr"
        assert setter._webserial is False

    def test_pinsetter_with_webserial(self):
        """Test PinSetter initialization with webserial attribute."""
        instance = Mock()
        instance.webserial = True
        instance.test_attr = False
        setter = PinSetter(instance, "test_attr")

        assert setter._webserial is True

    @pytest.mark.asyncio
    async def test_pinsetter_call_get(self):
        """Test PinSetter get value."""
        instance = Mock(spec=[])
        instance.test_attr = True
        setter = PinSetter(instance, "test_attr")

        result = await setter()
        assert result is True

    @pytest.mark.asyncio
    async def test_pinsetter_call_set(self):
        """Test PinSetter set value."""
        instance = Mock(spec=[])
        instance.test_attr = False
        setter = PinSetter(instance, "test_attr")

        result = await setter(True)
        assert instance.test_attr is True
        assert result is True

    @pytest.mark.asyncio
    async def test_pinsetter_call_webserial_set(self):
        """Test PinSetter set value with webserial."""
        instance = Mock()
        instance.webserial = True
        instance._test_attr = False
        instance.set_test_attr = AsyncMock()
        setter = PinSetter(instance, "test_attr")

        result = await setter(True)
        instance.set_test_attr.assert_called_once_with(True)
        assert result is None

    @pytest.mark.asyncio
    async def test_pinsetter_call_webserial_get(self):
        """Test PinSetter get value with webserial returns None."""
        instance = Mock()
        instance.webserial = True
        instance._test_attr = True
        setter = PinSetter(instance, "test_attr")

        result = await setter()
        assert result is None

    def test_pinsetter_get_instance(self):
        """Test PinSetter get_instance method."""
        instance = Mock()
        setter = PinSetter(instance, "test_attr")

        assert setter.get_instance() == instance


class TestBootloader:
    """Tests for Bootloader class."""

    def test_bootloader_initialization_simple(self):
        """Test Bootloader initialization with simple device."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        assert bootloader._device == "/dev/ttyUSB0"
        assert bootloader._serial == transport.serial
        assert bootloader._generic is True
        assert bootloader._smlight_net is False
        assert bootloader._gpio is False

    def test_bootloader_initialization_socket(self):
        """Test Bootloader initialization with socket device."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("socket://192.168.1.1:6638", transport)

        assert bootloader._device == "socket://192.168.1.1:6638"
        assert bootloader._smlight_net is True
        assert bootloader._host == "192.168.1.1"

    def test_set_mode_generic(self):
        """Test set_mode with generic mode."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        bootloader.set_mode("generic")
        assert bootloader._generic is True

    def test_set_mode_generic2(self):
        """Test set_mode with generic2 mode."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        bootloader.set_mode("generic2")
        assert bootloader._generic is False
        assert bootloader._generic2 is True

    def test_set_mode_network(self):
        """Test set_mode with network mode."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        bootloader.set_mode("network", host="192.168.1.1")
        assert bootloader._generic is False
        assert bootloader._smlight_net is True
        assert bootloader._host == "192.168.1.1"

    def test_set_mode_none(self):
        """Test set_mode with none mode."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        bootloader.set_mode("none")
        assert bootloader._generic is False

    def test_set_mode_gpio(self):
        """Test set_mode with GPIO config name."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        bootloader.set_mode("smhub")
        assert bootloader._generic is False
        assert bootloader._gpio is True
        assert bootloader._gpio_config is not None

    def test_set_gpio_config_valid(self):
        """Test set_gpio_config with valid config."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        bootloader.set_gpio_config("smhub")
        assert bootloader._gpio_config is not None

    def test_set_gpio_config_invalid(self):
        """Test set_gpio_config with invalid config."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        with pytest.raises(ValueError, match="GPIO config 'invalid' not found"):
            bootloader.set_gpio_config("invalid")

    def test_set_options(self):
        """Test set_options method."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        bootloader.set_options(dtr_active_high=True, inverted=True)
        assert bootloader._dtr_active_high is True
        assert bootloader._inverted is True

    @pytest.mark.asyncio
    async def test_invoke_bootloader_generic(self, mocker):
        """Test invoke_bootloader with generic mode."""
        transport = Mock()
        transport.serial = Mock(spec=[])
        transport.serial.dtr = False
        transport.serial.rts = False
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        await bootloader.invoke_bootloader()

        # Verify sleep was called
        asyncio.sleep.assert_called()

    @pytest.mark.asyncio
    async def test_invoke_bootloader_generic2(self, mocker):
        """Test invoke_bootloader with generic2 mode."""
        transport = Mock()
        transport.serial = Mock(spec=[])
        transport.serial.dtr = False
        transport.serial.rts = False
        bootloader = Bootloader("/dev/ttyUSB0", transport)
        bootloader.set_mode("generic2")

        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        await bootloader.invoke_bootloader()

        # Verify sleep was called
        asyncio.sleep.assert_called()

    @pytest.mark.asyncio
    async def test_invoke_bootloader_inverted(self, mocker):
        """Test invoke_bootloader with inverted pins."""
        transport = Mock()
        transport.serial = Mock(spec=[])
        transport.serial.dtr = False
        transport.serial.rts = False
        bootloader = Bootloader("/dev/ttyUSB0", transport)
        bootloader.set_options(dtr_active_high=False, inverted=True)

        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        await bootloader.invoke_bootloader()

        # Verify the pins were set up correctly (inverted: rts=bootloader, dtr=reset)
        assert hasattr(bootloader, "set_bootloader_pin")
        assert hasattr(bootloader, "set_reset_pin")

    @pytest.mark.asyncio
    async def test_invoke_bootloader_gpio(self, mocker):
        """Test invoke_bootloader with GPIO mode."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)
        bootloader.set_mode("smhub")

        mock_send = mocker.patch(
            "smlight_cc_flasher.gpio.send_gpio_pattern", new_callable=AsyncMock
        )
        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        await bootloader.invoke_bootloader()

        mock_send.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoke_bootloader_gpio_no_config(self):
        """Test invoke_bootloader with GPIO mode but no config set."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)
        bootloader._gpio = True
        bootloader._gpio_config = None

        with pytest.raises(ValueError, match="GPIO config not set"):
            await bootloader.invoke_gpio()

    @pytest.mark.asyncio
    async def test_invoke_bootloader_network(self, mocker):
        """Test invoke_bootloader with network mode."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("socket://192.168.1.1:6638", transport)

        # Mock the Api2 client
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.check_auth_needed = AsyncMock(return_value=False)
        mock_client.set_cmd = AsyncMock(return_value=True)

        mock_api = mocker.patch("pysmlight.web.Api2")
        mock_api.return_value = mock_client

        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        await bootloader.invoke_bootloader()

        mock_client.check_auth_needed.assert_called_once()
        mock_client.set_cmd.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoke_smlight_net_auth_needed(self, mocker):
        """Test invoke_smlight_net when auth is needed."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        # Mock the Api2 client
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.check_auth_needed = AsyncMock(return_value=True)

        mock_api = mocker.patch("pysmlight.web.Api2")
        mock_api.return_value = mock_client

        result = await bootloader.invoke_smlight_net("192.168.1.1")

        assert result is False
        mock_client.check_auth_needed.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoke_smlight_net_success(self, mocker):
        """Test invoke_smlight_net successful command."""
        transport = Mock()
        transport.serial = Mock()
        bootloader = Bootloader("/dev/ttyUSB0", transport)

        # Mock the Api2 client
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock()
        mock_client.check_auth_needed = AsyncMock(return_value=False)
        mock_client.set_cmd = AsyncMock(return_value=True)

        mock_api = mocker.patch("pysmlight.web.Api2")
        mock_api.return_value = mock_client

        result = await bootloader.invoke_smlight_net("192.168.1.1")

        assert result is True
        mock_client.check_auth_needed.assert_called_once()
        mock_client.set_cmd.assert_called_once()

    @pytest.mark.asyncio
    async def test_invoke_generic_dtr_active_high(self, mocker):
        """Test invoke_generic with dtr_active_high option."""
        transport = Mock()
        transport.serial = Mock(spec=[])
        transport.serial.dtr = False
        transport.serial.rts = False
        bootloader = Bootloader("/dev/ttyUSB0", transport)
        bootloader.set_options(dtr_active_high=True, inverted=False)

        # Set up the pin setters
        bootloader.set_bootloader_pin = PinSetter(transport.serial, "dtr")
        bootloader.set_reset_pin = PinSetter(transport.serial, "rts")

        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        await bootloader.invoke_generic()

        # Verify sleep was called
        asyncio.sleep.assert_called()


class TestCommandInterface:
    """Tests for CommandInterface class."""

    @pytest.mark.asyncio
    async def test_open(self, mocker):
        """Test opening serial connection."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.serial = Mock(spec=[])
        mock_writer.transport.get_extra_info = Mock(return_value=None)

        mocker.patch(
            "serial_asyncio.open_serial_connection",
            return_value=(mock_reader, mock_writer),
        )

        cmd_interface = CommandInterface()
        await cmd_interface.open("/dev/ttyUSB0", 500000)

        assert cmd_interface.reader == mock_reader
        assert cmd_interface.writer == mock_writer
        assert cmd_interface.webserial is False

    @pytest.mark.asyncio
    async def test_open_with_socket(self, mocker):
        """Test opening serial connection with TCP socket."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.serial = Mock()
        mock_writer.transport.serial.webserial = False

        mock_socket = Mock()
        mock_writer.transport.get_extra_info = Mock(return_value=mock_socket)

        mocker.patch(
            "serial_asyncio.open_serial_connection",
            return_value=(mock_reader, mock_writer),
        )

        cmd_interface = CommandInterface()
        await cmd_interface.open("socket://192.168.1.1:6638", 500000)

        mock_socket.setsockopt.assert_called_once()

    @pytest.mark.asyncio
    async def test_close(self, mocker):
        """Test closing serial connection."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.serial = Mock()
        mock_writer.transport.serial.webserial = False
        mock_writer.transport.get_extra_info = Mock(return_value=None)

        mocker.patch(
            "serial_asyncio.open_serial_connection",
            return_value=(mock_reader, mock_writer),
        )

        cmd_interface = CommandInterface()
        await cmd_interface.open("/dev/ttyUSB0", 500000)
        await cmd_interface.close()

        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_called_once()

    def test_transport_property(self, mocker):
        """Test transport property."""
        cmd_interface = CommandInterface()
        cmd_interface.writer = Mock()
        cmd_interface.writer.transport = Mock()

        assert cmd_interface.transport == cmd_interface.writer.transport

    @pytest.mark.asyncio
    async def test_wait_for_ack_success(self, mocker):
        """Test waiting for ACK successfully."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.transport = Mock()

        cmd_interface = CommandInterface()
        cmd_interface.reader = mock_reader
        cmd_interface.writer = mock_writer

        # Simulate receiving ACK
        mock_reader.read = AsyncMock(side_effect=[b"\x00", b"\xcc"])

        result = await cmd_interface._wait_for_ack(COMMAND.PING)
        assert result is True

    @pytest.mark.asyncio
    async def test_wait_for_ack_nack(self, mocker):
        """Test waiting for ACK but receiving NACK."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.transport = Mock()

        cmd_interface = CommandInterface()
        cmd_interface.reader = mock_reader
        cmd_interface.writer = mock_writer

        # Simulate receiving NACK
        mock_reader.read = AsyncMock(side_effect=[b"\x00", b"\x33"])

        result = await cmd_interface._wait_for_ack(COMMAND.PING)
        assert result is False

    @pytest.mark.asyncio
    async def test_wait_for_ack_timeout(self, mocker):
        """Test waiting for ACK timeout."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.transport = Mock()

        cmd_interface = CommandInterface()
        cmd_interface.reader = mock_reader
        cmd_interface.writer = mock_writer

        # Simulate timeout
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError)

        with pytest.raises(CmdException, match="Timeout waiting for ACK/NACK"):
            await cmd_interface._wait_for_ack(COMMAND.PING)

    @pytest.mark.asyncio
    async def test_wait_for_ack_timeout_synch(self, mocker):
        """Test waiting for ACK timeout during SYNCH command."""
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.transport = Mock()

        cmd_interface = CommandInterface()
        cmd_interface.reader = mock_reader
        cmd_interface.writer = mock_writer

        # Simulate timeout during SYNCH
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError)

        with pytest.raises(asyncio.TimeoutError):
            await cmd_interface._wait_for_ack(COMMAND.SYNCH)

    def test_encode_addr(self):
        """Test encoding address."""
        cmd_interface = CommandInterface()
        result = cmd_interface._encode_addr(0x12345678)
        assert result == b"\x12\x34\x56\x78"

    def test_decode_addr(self):
        """Test decoding address."""
        cmd_interface = CommandInterface()
        result = cmd_interface._decode_addr(b"\x12\x34\x56\x78")
        assert result == 0x12345678

    @pytest.mark.asyncio
    async def test_write_int(self, mocker):
        """Test writing integer data."""
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.get_write_buffer_size = Mock(return_value=0)

        cmd_interface = CommandInterface()
        cmd_interface.writer = mock_writer
        cmd_interface.webserial = False

        await cmd_interface._write(0x55)

        mock_writer.write.assert_called_once_with(b"\x55")
        mock_writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_write_bytes(self, mocker):
        """Test writing bytes data."""
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.get_write_buffer_size = Mock(return_value=0)

        cmd_interface = CommandInterface()
        cmd_interface.writer = mock_writer
        cmd_interface.webserial = False

        await cmd_interface._write(b"\x01\x02\x03")

        mock_writer.write.assert_called_once_with(b"\x01\x02\x03")
        mock_writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_write_webserial(self, mocker):
        """Test writing with webserial."""
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.transport = Mock()

        cmd_interface = CommandInterface()
        cmd_interface.writer = mock_writer
        cmd_interface.webserial = True

        await cmd_interface._write(b"\x01\x02\x03")

        mock_writer.write.assert_called_once_with(b"\x01\x02\x03")
        mock_writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_sendCmd_simple(self, mocker):
        """Test sending simple command."""
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.get_write_buffer_size = Mock(return_value=0)

        cmd_interface = CommandInterface()
        cmd_interface.writer = mock_writer
        cmd_interface.webserial = False

        await cmd_interface._sendCmd(COMMAND.PING)

        mock_writer.write.assert_called_once()
        mock_writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_sendCmd_with_addr(self, mocker):
        """Test sending command with address."""
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.get_write_buffer_size = Mock(return_value=0)

        cmd_interface = CommandInterface()
        cmd_interface.writer = mock_writer
        cmd_interface.webserial = False

        await cmd_interface._sendCmd(COMMAND.DOWNLOAD, addr=0x1000, size=0x100)

        mock_writer.write.assert_called_once()
        mock_writer.drain.assert_called_once()

    @pytest.mark.asyncio
    async def test_receivePacket_success(self, mocker):
        """Test receiving packet successfully."""
        mock_reader = AsyncMock()
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.get_write_buffer_size = Mock(return_value=0)

        cmd_interface = CommandInterface()
        cmd_interface.reader = mock_reader
        cmd_interface.writer = mock_writer
        cmd_interface.webserial = False

        # Simulate packet: size=4, checksum=0x06, data=b"\x01\x02\x03"
        mock_reader.readexactly = AsyncMock(side_effect=[b"\x04\x06", b"\x01\x02\x03"])

        result = await cmd_interface.receivePacket()

        assert result == b"\x01\x02\x03"
        mock_writer.write.assert_called_once_with(CommandInterface.ACK)

    @pytest.mark.asyncio
    async def test_receivePacket_checksum_error(self, mocker):
        """Test receiving packet with checksum error."""
        mock_reader = AsyncMock()
        mock_writer = Mock()
        mock_writer.write = Mock()
        mock_writer.drain = AsyncMock()
        mock_writer.transport = Mock()
        mock_writer.transport.get_write_buffer_size = Mock(return_value=0)

        cmd_interface = CommandInterface()
        cmd_interface.reader = mock_reader
        cmd_interface.writer = mock_writer
        cmd_interface.webserial = False

        # Simulate packet with wrong checksum
        mock_reader.readexactly = AsyncMock(side_effect=[b"\x04\xff", b"\x01\x02\x03"])

        with pytest.raises(CmdException, match="checksum error"):
            await cmd_interface.receivePacket()

        mock_writer.write.assert_called_once_with(CommandInterface.NACK)

    @pytest.mark.asyncio
    async def test_cmdMemWrite_width_mismatch(self):
        """Test cmdMemWrite with width mismatch."""
        cmd_interface = CommandInterface()

        with pytest.raises(ValueError, match="width does not match len"):
            await cmd_interface.cmdMemWrite(0x1000, b"\x01\x02", 4)

    @pytest.mark.asyncio
    async def test_cmdMemWrite_invalid_width(self):
        """Test cmdMemWrite with invalid width."""
        cmd_interface = CommandInterface()

        with pytest.raises(ValueError, match="width must be 1 or 4"):
            await cmd_interface.cmdMemWrite(0x1000, b"\x01\x02", 2)

    @pytest.mark.asyncio
    async def test_cmdDownload_invalid_size(self):
        """Test cmdDownload with invalid data size."""
        cmd_interface = CommandInterface()

        with pytest.raises(CmdException, match="Invalid data size"):
            await cmd_interface.cmdDownload(0x1000, 5)

    @pytest.mark.asyncio
    async def test_cmdDownloadCRC32_invalid_size(self):
        """Test cmdDownloadCRC32 with invalid data size."""
        cmd_interface = CommandInterface()

        with pytest.raises(CmdException, match="Invalid data size"):
            await cmd_interface.cmdDownloadCRC32(0x1000, 7, 0x12345678)
