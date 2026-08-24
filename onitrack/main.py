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
    auth_subparsers.add_parser(
        "upgrade",
        help="prepare encrypted Apple registration state",
    )
    auth_parser.set_defaults(_command_parser=auth_parser)

    apple_parser = subparsers.add_parser("apple", help="manage Apple registration")
    apple_parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="config directory (default: .config/onitrack)",
    )
    apple_subparsers = apple_parser.add_subparsers(dest="apple_command")
    apple_subparsers.add_parser("register", help="prepare encrypted APNs/IDS state")
    apple_parser.set_defaults(_command_parser=apple_parser)

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
    people_alias_parser = people_subparsers.add_parser(
        "alias",
        help="manage configured People aliases",
    )
    people_alias_subparsers = people_alias_parser.add_subparsers(
        dest="people_alias_command",
    )
    people_alias_set_parser = people_alias_subparsers.add_parser(
        "set",
        help="bind an alias to an anonymized person_id",
    )
    people_alias_set_parser.add_argument("alias")
    people_alias_set_parser.add_argument("person_id", metavar="PERSON_ID")
    people_alias_setup_parser = people_alias_subparsers.add_parser(
        "setup",
        help="interactively bind an alias to an accepted relationship",
    )
    people_location_parser = people_subparsers.add_parser(
        "location",
        help="fetch configured People locations",
    )
    people_location_subparsers = people_location_parser.add_subparsers(
        dest="people_location_command",
    )
    people_location_get_parser = people_location_subparsers.add_parser(
        "get",
        help="fetch one configured alias location",
    )
    people_location_get_parser.add_argument("--alias", required=True)
    people_location_get_parser.add_argument(
        "--anonomyse",
        action="store_true",
        help="print anonymized location diagnostics",
    )
    people_location_get_parser.add_argument(
        "--plain",
        action="store_true",
        help="print raw location data",
    )
    people_location_get_parser.add_argument(
        "--debug-redacted",
        action="store_true",
        help="print redacted protocol diagnostics to stderr",
    )
    people_parser.set_defaults(_command_parser=people_parser)
    people_list_parser.set_defaults(_command_parser=people_list_parser)
    people_alias_parser.set_defaults(_command_parser=people_alias_parser)
    people_alias_set_parser.set_defaults(_command_parser=people_alias_set_parser)
    people_alias_setup_parser.set_defaults(_command_parser=people_alias_setup_parser)
    people_location_parser.set_defaults(_command_parser=people_location_parser)
    people_location_get_parser.set_defaults(_command_parser=people_location_get_parser)

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
            from onitrack.auth import print_status, provision, upgrade

            match args.auth_command:
                case "provision":
                    return provision(resolve_config_dir(args.config_dir))
                case "status":
                    return print_status(resolve_config_dir(args.config_dir))
                case "upgrade":
                    return upgrade(resolve_config_dir(args.config_dir))
                case None:
                    args._command_parser.error("auth requires a subcommand")
        case "apple":
            from onitrack.auth import upgrade

            match args.apple_command:
                case "register":
                    return upgrade(resolve_config_dir(args.config_dir))
                case None:
                    args._command_parser.error("apple requires a subcommand")
        case "people":
            from onitrack.people import (
                get_people_location,
                list_people,
                set_people_alias,
                setup_people_alias,
            )

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
                case "alias":
                    match args.people_alias_command:
                        case "set":
                            return set_people_alias(
                                resolve_config_dir(args.config_dir),
                                alias=args.alias,
                                person_id=args.person_id,
                            )
                        case "setup":
                            return setup_people_alias(
                                resolve_config_dir(args.config_dir),
                            )
                        case None:
                            args._command_parser.error(
                                "people alias requires a subcommand",
                            )
                case "location":
                    match args.people_location_command:
                        case "get":
                            if not args.anonomyse and not args.plain:
                                args._command_parser.error(
                                    "choose --anonomyse or --plain",
                                )
                            if args.anonomyse and args.plain:
                                args._command_parser.error(
                                    "choose only one of --anonomyse or --plain",
                                )
                            return get_people_location(
                                resolve_config_dir(args.config_dir),
                                alias=args.alias,
                                anonymise=args.anonomyse,
                                debug_redacted=args.debug_redacted,
                            )
                        case None:
                            args._command_parser.error(
                                "people location requires a subcommand",
                            )
                case None:
                    args._command_parser.error("people requires a subcommand")
        case None:
            parser.print_help()
            return 0

    parser.error(f"unknown command: {args.command}")
    return 2
