from gatox.cli.colors import Fore, Style
from gatox.util.arg_utils import StringType


def configure_parser_search(parser):
    """Helper method to add arguments to the search subparser.

    Args:
        parser: Add arguments to the search module subparser.
    """
    parser.add_argument(
        "--target",
        "-t",
        help="Organization to enumerate using GitHub code search.",
        metavar=f"{Fore.RED}ORGANIZATION{Style.RESET_ALL}",
        required=False,
    )

    parser.add_argument(
        "--query",
        "-q",
        help="Pass a custom query to GitHub code search",
        metavar="QUERY",
        required=False,
    )

    parser.add_argument(
        "--sourcegraph",
        "-sg",
        help="Use Sourcegraph API to search for self-hosted runners.",
        required=False,
        action="store_true",
    )

    parser.add_argument(
        "--output-text",
        "-oT",
        help=("Save enumeration output to text file."),
        metavar="TEXT_FILE",
        type=StringType(256),
    )
