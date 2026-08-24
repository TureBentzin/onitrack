from __future__ import annotations

import argparse

from onitrack import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onitrack",
        description="",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("version", help="print the onitrack version")
    subparsers.add_parser("doctor", help="check the base environment")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    match args.command:
        case "version":
            print(__version__)
            return 0
        case "doctor":
            print("onitrack base environment available")
            return 0
        case None:
            parser.print_help()
            return 0

    parser.error(f"unknown command: {args.command}")
    return 2
