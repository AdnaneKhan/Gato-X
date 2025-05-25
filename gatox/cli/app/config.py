"""Configuration for the app command."""

import os
import argparse
from pathlib import Path
from colorama import Fore, Style


class ReadableFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        prospective_file = Path(values)
        if not prospective_file.exists():
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} {prospective_file} does not exist!"
            )
        if not prospective_file.is_file():
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} {prospective_file} is not a file!"
            )
        if not os.access(prospective_file, os.R_OK):
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} {prospective_file} is not readable!"
            )
        setattr(namespace, self.dest, values)


def configure_parser_app(parser):
    """Configure the app command parser.

    Args:
        parser: The parser to configure
    """
    parser.add_argument(
        "--app",
        help="GitHub App ID",
        required=True,
    )

    parser.add_argument(
        "--pem",
        help=(
            "Path to the private key file (PEM format) for GitHub App authentication"
        ),
        required=True,
        action=ReadableFile,
    )

    # Command options
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--installations",
        help=("List all installations for the GitHub App and their metadata"),
        action="store_true",
    )

    group.add_argument(
        "--installation",
        help=("Specific installation ID to enumerate"),
        metavar="INSTALLATION_ID",
    )

    group.add_argument(
        "--full",
        help=("Full enumeration of all installations accessible to the GitHub App"),
        action="store_true",
    )
