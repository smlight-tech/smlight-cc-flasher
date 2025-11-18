"""Tests for GPIO module."""

import pytest

from smlight_cc_flasher.gpio import GpioPattern, send_gpio_pattern


def test_gpio_pattern_dataclass():
    """Test GpioPattern dataclass creation."""
    pattern = GpioPattern(pins={11: True, 12: False}, delay_after=0.5)

    assert pattern.pins == {11: True, 12: False}
    assert pattern.delay_after == 0.5


def test_gpio_config_dataclass(sample_gpio_config):
    """Test GpioConfig dataclass creation."""
    assert sample_gpio_config.chip == "gpiochip0"
    assert len(sample_gpio_config.patterns) == 3
    assert sample_gpio_config.patterns[0].pins == {11: True, 12: False}
    assert sample_gpio_config.patterns[1].pins == {11: False, 12: False}
    assert sample_gpio_config.patterns[2].pins == {11: True, 12: True}
    assert all(p.delay_after == 0.1 for p in sample_gpio_config.patterns)


@pytest.mark.asyncio
async def test_send_gpio_pattern_basic(mock_gpiod, mocker, sample_gpio_config):
    """Test basic GPIO pattern sending."""
    mocker.patch("smlight_cc_flasher.gpio.time.sleep")

    await send_gpio_pattern(sample_gpio_config.chip, sample_gpio_config.patterns)

    mock_gpiod.request_lines.assert_called_once()
    call_args = mock_gpiod.request_lines.call_args
    assert call_args[1]["path"] == f"/dev/{sample_gpio_config.chip}"
    assert call_args[1]["consumer"] == "smlight-cc-flasher"

    mock_request = mock_gpiod.request_lines.return_value.__enter__.return_value
    assert mock_request.set_values.call_count == len(sample_gpio_config.patterns) - 1
