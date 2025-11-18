import asyncio

from .cli import main as entry


def main() -> None:
    asyncio.run(entry())


if __name__ == "__main__":
    main()
