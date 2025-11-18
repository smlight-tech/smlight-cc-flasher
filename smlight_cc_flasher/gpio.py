import asyncio
import dataclasses
import logging
import time

import gpiod

logger = logging.getLogger(__name__)


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


def _send_gpio_pattern(chip: str, pattern: list[GpioPattern]) -> None:  # noqa: UP031
    """Send GPIO pattern to chip."""
    logger.debug("Sending GPIO pattern to chip %s", chip)  # noqa: UP031

    line_config = {
        pin: gpiod.LineSettings(
            direction=gpiod.line.Direction.OUTPUT,
            output_value=gpiod.line.Value(state),
        )
        for pin, state in pattern[0].pins.items()
    }

    with gpiod.request_lines(
        chip,
        consumer="smlight-cc-flasher",
        config=line_config,
    ) as request:
        time.sleep(pattern[0].delay_after)

        for step in pattern[1:]:
            values = {pin: gpiod.line.Value(state) for pin, state in step.pins.items()}
            request.set_values(values)
            time.sleep(step.delay_after)


async def send_gpio_pattern(chip: str, pattern: list[GpioPattern]) -> None:
    """Send GPIO pattern to chip asynchronously."""
    await asyncio.get_running_loop().run_in_executor(
        None, _send_gpio_pattern, chip, pattern
    )
