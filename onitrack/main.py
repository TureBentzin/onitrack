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
    auth_parser.set_defaults(_command_parser=auth_parser)

    people_parser = subparsers.add_parser("people", help="inspect Find My People")
    people_parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="config directory (default: .config/onitrack)",
    )
    people_subparsers = people_parser.add_subparsers(dest="people_command")
    people_list_parser = people_subparsers.add_parser(
        "list",
        help="list accepted People location shares",
    )
    people_list_parser.add_argument(
        "--anonomyse",
        action="store_true",
        help="print anonymized relationship identifiers",
    )
    people_list_parser.add_argument(
        "--plain",
        action="store_true",
        help="print raw relationship identifiers",
    )
    people_parser.set_defaults(_command_parser=people_parser)
    people_list_parser.set_defaults(_command_parser=people_list_parser)

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
                    args._command_parser.error("auth requires a subcommand")
        case "people":
            from onitrack.people import list_people

            match args.people_command:
                case "list":
                    if not args.anonomyse and not args.plain:
                        args._command_parser.error("choose --anonomyse or --plain")
                    if args.anonomyse and args.plain:
                        args._command_parser.error(
                            "choose only one of --anonomyse or --plain",
                        )
                    return list_people(
                        resolve_config_dir(args.config_dir),
                        anonymise=args.anonomyse,
                    )
                case None:
                    args._command_parser.error("people requires a subcommand")
        case None:
            parser.print_help()
            return 0

    parser.error(f"unknown command: {args.command}")
    return 2
