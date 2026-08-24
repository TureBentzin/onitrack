from __future__ import annotations

import argparse
from pathlib import Path

from onitrack import __version__
from onitrack.state import resolve_config_dir


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

    auth_parser = subparsers.add_parser("auth", help="manage Apple Account auth")
    auth_parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="config directory (default: .config/onitrack)",
    )
    auth_parser.add_argument(
        "--state-dir",
        dest="config_dir",
        type=Path,
        default=None,
        help=argparse.SUPPRESS,
    )
    auth_subparsers = auth_parser.add_subparsers(dest="auth_command")
    auth_subparsers.add_parser("provision", help="interactively provision auth state")
    auth_subparsers.add_parser("status", help="show offline auth state status")

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
        case "auth":
            from onitrack.auth import print_status, provision

            match args.auth_command:
                case "provision":
                    return provision(resolve_config_dir(args.config_dir))
                case "status":
                    return print_status(resolve_config_dir(args.config_dir))
                case None:
                    parser.error("auth requires a subcommand")
        case None:
            parser.print_help()
            return 0

    parser.error(f"unknown command: {args.command}")
    return 2
