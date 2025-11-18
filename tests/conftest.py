"""Pytest configuration and fixtures for smlight_cc_flasher tests."""

import pytest

from smlight_cc_flasher.gpio import GpioConfig, GpioPattern


@pytest.fixture
def mock_gpiod(mocker):
    """Mock gpiod module."""
    mocker.patch("smlight_cc_flasher.gpio.os.path.exists", return_value=True)

    mock = mocker.patch("smlight_cc_flasher.gpio.gpiod")

    mock.LineSettings.return_value = mocker.MagicMock()

    mock_request = mocker.MagicMock()
    mock.request_lines.return_value.__enter__.return_value = mock_request
    mock.request_lines.return_value.__exit__.return_value = None

    mock.line.Direction.OUTPUT = "OUTPUT"
    mock.line.Value.return_value = mocker.MagicMock()

    return mock


@pytest.fixture
def sample_gpio_config():
    """Sample GPIO configuration for testing."""
    return GpioConfig(
        chip="gpiochip0",
        patterns=[
            GpioPattern(pins={11: True, 12: False}, delay_after=0.1),
            GpioPattern(pins={11: False, 12: False}, delay_after=0.1),
            GpioPattern(pins={11: True, 12: True}, delay_after=0.1),
        ],
    )
