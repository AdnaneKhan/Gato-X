from gatox.util.arg_utils import ReadableFile, StringType
from gatox.cli.output import Output
from gatox.cli.colors import Fore, Style


def configure_parser_pwnrequest(parser):
    """Helper method to add arguments to the pwnrequest subparser.

    Args:
        parser: The parser to add pwnrequest subarguments to.
    """
    parser.add_argument(
        "--target",
        "-t",
        help="Repository to target.",
        metavar=f"{Fore.RED}ORG/REPO{Style.RESET_ALL}",
        required=True,
        type=StringType(80),
    )
    parser.add_argument(
        "--attack-template",
        "-at",
        help=(
            "Path to an attack template YAML file which will be used to drive the "
            "pwnrequest attack module."
        ),
        metavar=f"{Fore.GREEN}PATH/TO/FILE.YML{Style.RESET_ALL}",
        required=True,
        type=ReadableFile(),
    )

    parser.add_argument(
        "--timeout",
        "-to",
        metavar="SECONDS",
        help=(
            "Timeout, in seconds, to wait for the Workflow to queue and execute. "
            "Defaults to '30'."
        ),
        default="30",
        type=int,
    )
