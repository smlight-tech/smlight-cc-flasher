import asyncio
import dataclasses
import logging
import os
import time

import gpiod

logger = logging.getLogger(__name__)


def _resolve_chip_path(chip: str) -> str:
    """Resolve chip name to full device path."""
    if chip.startswith("/dev"):
        return chip

    chip_path = f"/dev/{chip}"
    if not os.path.exists(chip_path):
        raise FileNotFoundError(f"GPIO chip '{chip}' not found at {chip_path}. ")
    return chip_path


@dataclasses.dataclass
class GpioPattern:
    pins: dict[int, bool]
    delay_after: float


@dataclasses.dataclass
class GpioConfig:
    chip: str
    patterns: list[GpioPattern]


gpioResets = {
    "smhub": GpioConfig(
        chip="gpiochip1",
        patterns=[
            GpioPattern(pins={11: True, 12: True}, delay_after=0.1),
            GpioPattern(pins={11: False, 12: False}, delay_after=0.1),
            GpioPattern(pins={11: True, 12: False}, delay_after=0.1),
            GpioPattern(pins={11: True, 12: True}, delay_after=0.1),
        ],
    )
}


def _send_gpio_pattern(chip: str, pattern: list[GpioPattern]) -> None:
    """Send GPIO pattern to chip."""
    logger.debug("Sending GPIO pattern to chip %s", chip)  # noqa: UP031

    chip_path = _resolve_chip_path(chip)

    line_config: dict[int | str, gpiod.LineSettings] = {
        pin: gpiod.LineSettings(
            direction=gpiod.line.Direction.OUTPUT,
            output_value=gpiod.line.Value(state),
        )
        for pin, state in pattern[0].pins.items()
    }

    with gpiod.request_lines(
        path=chip_path,
        consumer="smlight-cc-flasher",
        config=line_config,  # type: ignore[arg-type]
    ) as request:
        time.sleep(pattern[0].delay_after)

        for step in pattern[1:]:
            values: dict[int | str, gpiod.line.Value] = {
                pin: gpiod.line.Value(state) for pin, state in step.pins.items()
            }
            request.set_values(values)
            time.sleep(step.delay_after)


async def send_gpio_pattern(chip: str, pattern: list[GpioPattern]) -> None:
    """Send GPIO pattern to chip asynchronously."""
    await asyncio.get_running_loop().run_in_executor(
        None, _send_gpio_pattern, chip, pattern
    )
