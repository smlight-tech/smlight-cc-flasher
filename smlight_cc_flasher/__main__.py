import asyncio

from .cli import main as entry


def main():
    asyncio.run(entry())


if __name__ == "__main__":
    main()
