
from gatox.cli.output import Fore, Style, Output
from gatox.util.arg_utils import StringType, ReadableFile, WriteableDir

def configure_parser_enumerate(parser):
    """Helper method to add arguments to the enumeration subparser.

    Args:
        parser: sub parser to add arguments to.
    """

    parser.add_argument(
        "--target", "-t",
        help="Target an organization to enumerate for self-hosted runners.",
        metavar=f"{Fore.RED}ORGANIZATION{Style.RESET_ALL}",
        type=StringType(39)
    )

    parser.add_argument(
        "--repository", "-r",
        help="Target a single repository in org/repo format to enumerate for\n"
        "self-hosted runners.",
        metavar=f"{Fore.RED}ORG/REPO_NAME{Style.RESET_ALL}",
        type=StringType(79, regex=r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+")
    )

    parser.add_argument(
        "--repositories", "-R",
        help="A text file containing repositories in org/repo format to\n"
        "enumerate for self-hosted runners.",
        metavar=f"{Fore.RED}PATH/TO/FILE.txt{Style.RESET_ALL}",
        type=ReadableFile()
    )

    parser.add_argument(
        "--self-enumeration", "-s",
        help=(
            "Enumerate the configured token's access and all repositories or\n"
            "organizations the user has write access to."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--validate", "-v",
        help=(
            "Validate if the token is valid and print organization memberships."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--output-yaml", "-o",
        help=(
            "Directory to save gathered workflow yml files to. Will be\n"
            f"created in the following format: {Fore.GREEN}"
            f"org/repo/workflow.yml{Style.RESET_ALL}"
        ),
        metavar="DIR",
        type=WriteableDir()
    )

    parser.add_argument(
        "--skip-runners", "-sr",
        help=(
            f"Do {Output.bright('NOT')} enumerate runners via run-log analysis, this will\n"
            "speed up the enumeration, but will miss self-hosted runners for\n"
            "non-admin users."
        ),
        action="store_true",
    )

    parser.add_argument(
        "--output-json", "-oJ",
        help=(
            "Save enumeration output to JSON file."
        ),
        metavar="JSON_FILE",
        type=StringType(256)
    )