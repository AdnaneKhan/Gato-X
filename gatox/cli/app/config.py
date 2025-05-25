from gatox.cli.output import Fore, Style, Output
from gatox.util.arg_utils import StringType, ReadableFile


def configure_parser_app(parser):
    """Helper method to add arguments to the app subparser.

    Args:
        parser: sub parser to add arguments to.
    """

    # Add general arguments
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="CRITICAL",
        required=False,
    )

    parser.add_argument(
        "--socks-proxy",
        "-sp",
        help=(
            "SOCKS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format"
        ),
        required=False,
    )

    parser.add_argument(
        "--http-proxy",
        help=(
            "HTTPS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format."
        ),
        required=False,
    )

    parser.add_argument(
        "--no-color", "-nc", help="Removes all color from output.", action="store_true"
    )

    parser.add_argument(
        "--app",
        "-a",
        help="GitHub App ID to authenticate with.",
        metavar=f"{Fore.RED}APP_ID{Style.RESET_ALL}",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--pem",
        help="Path to the GitHub App private key PEM file.",
        metavar=f"{Fore.RED}PATH/TO/PRIVATE_KEY.pem{Style.RESET_ALL}",
        type=ReadableFile(),
        required=True,
    )

    # Create mutually exclusive group for the different operation modes
    operation_group = parser.add_mutually_exclusive_group(required=True)

    operation_group.add_argument(
        "--installations",
        "-i",
        help="List all app installations with metadata including repositories and permissions.",
        action="store_true",
    )

    operation_group.add_argument(
        "--full",
        "-f",
        help="Perform full enumeration on all maximally visible repositories across all installations.",
        action="store_true",
    )

    operation_group.add_argument(
        "--installation",
        "-I",
        help="Enumerate a specific installation by ID.",
        metavar=f"{Fore.RED}INSTALLATION_ID{Style.RESET_ALL}",
        type=int,
    )

    parser.add_argument(
        "--output-json",
        "-oJ",
        help="Save enumeration output to JSON file.",
        metavar="JSON_FILE",
        type=StringType(256),
    )

    parser.add_argument(
        "--skip-runners",
        "-sr",
        help=(
            f"Do {Output.bright('NOT')} enumerate runners via run-log analysis, this will\n"
            "speed up the enumeration, but will miss self-hosted runners for\n"
            "non-admin users."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--deep-dive",
        "-dd",
        help=(
            "Perform deep dive static analysis, which includes analyzing non-default branches for Pwn Request vulnerabilities.\n"
            "Git is required on the PATH for this feature."
        ),
        action="store_true",
    )
