import argparse
import os
import re

from packaging import version

from colorama import Fore, Style

from gatox import util
from gatox.cli.colors import RED_DASH
from gatox.cli.output import Output
from gatox.cli.enumeration.config import configure_parser_enumerate
from gatox.cli.search.config import configure_parser_search
from gatox.cli.attack.config import configure_parser_attack
from gatox.enumerate.enumerate import Enumerator
from gatox.attack.attack import Attacker
from gatox.attack.runner.webshell import WebShell
from gatox.attack.secrets.secrets_attack import SecretsAttack
from gatox.search.search import Searcher
from gatox.models.execution import Execution


def cli(args):
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            f'{Fore.YELLOW}This tool requires a GitHub PAT to'
            f' function!{Style.RESET_ALL}\n\nThis can be passed via the'
            ' "GH_TOKEN" environment variable, or if it is not set,\nthen the'
            ' application will prompt you for one.'
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    configure_parser_general(parser)

    parser.add_argument(
        "--api-url", "-u",
        help=(
            f"{Fore.RED}{Output.bright('!! Experimental !!')}\n"
            "Github API URL to target. \n"
            "Defaults to 'https://api.github.com'"
        ),
        metavar="https://api.github-url.com/api/v3",
        required=False,
    )

    attack_parser = subparsers.add_parser(
        "attack", help="CI/CD Attack Capabilities", aliases=["a"],
        formatter_class=argparse.RawTextHelpFormatter
    )
    attack_parser.set_defaults(func=attack)

    enumerate_parser = subparsers.add_parser(
        "enumerate", help="Enumeration Capabilities", aliases=["enum", "e"],
        formatter_class=argparse.RawTextHelpFormatter
    )
    enumerate_parser.set_defaults(func=enumerate)

    search_parser = subparsers.add_parser(
        "search", help="Search Capabilities Using GitHub's API", aliases=["s"],
        formatter_class=argparse.RawTextHelpFormatter
    )
    search_parser.set_defaults(func=search)

    configure_parser_attack(attack_parser)
    configure_parser_enumerate(enumerate_parser)
    configure_parser_search(search_parser)

    arguments = parser.parse_args(args)

    Output(not arguments.no_color)

    validate_arguments(arguments, parser)

    arguments.func(arguments, subparsers)

def validate_arguments(args, parser):
    if "GH_TOKEN" not in os.environ:
        gh_token = input(
            "No 'GH_TOKEN' environment variable set! Please enter a GitHub"
            " PAT.\n"
        )
    else:
        gh_token = os.environ["GH_TOKEN"]

    if "github_pat_" in gh_token:
        parser.error(
            f"{Fore.RED}[!] Fine-grained PATs are currently not supported!"
        )

    if not ("ghp_" in gh_token or "gho_" in gh_token or "ghu_" in
            gh_token or re.match('^[a-fA-F0-9]{40}$', gh_token)):
        parser.error(f"{Fore.RED}[!]{Style.RESET_ALL} Provided GitHub PAT is"
                     " malformed!")

    args_dict = vars(args)
    args_dict["gh_token"] = gh_token

    if args.socks_proxy and args.http_proxy:
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} You cannot use a SOCKS and HTTP"
            " proxy at the same time!"
        )

def attack(args, parser):
    parser = parser.choices["attack"]

    if not args.target and not (args.interact or args.payload_only):
        parser.error(
            f"{Fore.RED}[!] You must select a target unless you are interacting with an implant or generating payloads!"
        )

    if not (args.workflow or args.runner_on_runner or args.secrets or args.interact or args.payload_only):
        parser.error(f"{Fore.RED}[!] You must select one of the attack modes, "
                     "workflow, runner_on_runner, secrets, or interact.")

    if args.custom_file and (args.command or
                             args.name):
        parser.error(f"{Fore.RED}[!] A shell command or workflow name"
                     f" cannot be used with a custom workflow.")

    if args.secrets and args.command:
        parser.error(
            f"{Fore.RED}[!] A command cannot be used with secrets exfil!."
        )

    if args.runner_on_runner and args.command:
        parser.error(
            f"{Fore.RED}[!] A command cannot be used with runner-on-runner attacks!."
        )

    if not args.custom_file:
        args.command = args.command if args.command else "whoami"
        args.name = args.name if args.name else "test"

    if args.runner_on_runner and not (args.target_os or args.target_arch):
        parser.error(
            f"{Fore.RED}[!] You must specify a target OS and architecture for runner-on-runner attacks!"
        )

    if args.payload_only and not (args.target_os or args.target_arch):
         parser.error(
            f"{Fore.RED}[!] You must specify a target OS, architecture, and C2 Repo for runner-on-runner payload generation!"
        )

    if args.runner_on_runner:
        if (args.target_os == 'windows' or args.target_os == "osx") and args.target_arch == 'arm':
            parser.error(
                f"{Fore.RED}[!] Windows and OSX do not support arm32 architecture!"
            )

    timeout = int(args.timeout)

    if args.runner_on_runner or args.payload_only or args.interact:
        if not args.branch:
            args.branch = 'main'

        gh_attack_runner = WebShell(
                args.gh_token,
                author_email=args.author_email,
                author_name=args.author_name,
                socks_proxy=args.socks_proxy,
                http_proxy=args.http_proxy,
                timeout=timeout,
                github_url=args.api_url
            )
        
        if args.payload_only:
            gh_attack_runner.payload_only(
                args.payload_only,
                args.target_os,
                args.target_arch,
                args.labels
            )
        elif args.runner_on_runner:
            gh_attack_runner.runner_on_runner(
                args.target,
                args.branch,
                args.pr_title,
                args.source_branch,
                args.message,
                args.target_os,
                args.target_arch,
                args.labels,
                keep_alive=args.keep_alive,
                run_name=args.name,
                workflow_name=args.name
            )
        elif args.interact:
            gh_attack_runner.interact_webshell(
                args.interact
            )

    elif args.workflow:
        gh_attack_runner = Attacker(
                args.gh_token,
                author_email=args.author_email,
                author_name=args.author_name,
                socks_proxy=args.socks_proxy,
                http_proxy=args.http_proxy,
                timeout=timeout,
                github_url=args.api_url
        )
        gh_attack_runner.push_workflow_attack(
            args.target,
            args.command,
            args.custom_file,
            args.branch,
            args.message,
            args.delete_run,
            args.file_name
        )
    elif args.secrets:

        gh_attack_runner = SecretsAttack(
                args.gh_token,
                author_email=args.author_email,
                author_name=args.author_name,
                socks_proxy=args.socks_proxy,
                http_proxy=args.http_proxy,
                timeout=timeout,
                github_url=args.api_url
            )

        gh_attack_runner.secrets_dump(
            args.target,
            args.branch,
            args.message,
            args.delete_run,
            args.file_name
        )

def enumerate(args, parser):
    parser = parser.choices["enumerate"]

    if not (args.target or args.self_enumeration or
            args.repository or args.repositories or args.validate):
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} No enumeration type was"
            " specified!"
        )

    if sum(bool(x) for x in [args.target, args.self_enumeration,
                             args.repository, args.repositories,
                             args.validate]) != 1:
        parser.error(
            f"{Fore.RED}[-]{Style.RESET_ALL} You must only select one "
            "enumeration type."
        )

    gh_enumeration_runner = Enumerator(
            args.gh_token,
            socks_proxy=args.socks_proxy,
            http_proxy=args.http_proxy,
            output_yaml=args.output_yaml,
            skip_log=args.skip_runners,
            github_url=args.api_url
        )

    exec_wrapper = Execution()
    orgs = []
    repos = []

    if args.validate:
        orgs = gh_enumeration_runner.validate_only()
    elif args.self_enumeration:
        orgs = gh_enumeration_runner.self_enumeration()
    elif args.target:
        orgs = [gh_enumeration_runner.enumerate_organization(
            args.target
        )]
    elif args.repositories:
        try:
            repo_list = util.read_file_and_validate_lines(
                args.repositories,
                r"[A-Za-z0-9-_.]+\/[A-Za-z0-9-_.]+"
            )
            repos = gh_enumeration_runner.enumerate_repos(repo_list)
        except argparse.ArgumentError as e:
            parser.error(
                f"{RED_DASH} The file contained an invalid repository name!"
                f"{Output.bright(e)}"
            )
    elif args.repository:
        repos = [gh_enumeration_runner.enumerate_repo_only(
            args.repository
        )]

    exec_wrapper.set_user_details(gh_enumeration_runner.user_perms)
    exec_wrapper.add_organizations(orgs)
    exec_wrapper.add_repositories(repos)

    if args.output_json:
        Output.write_json(exec_wrapper, args.output_json)


def search(args, parser):
    parser = parser.choices["search"]

    gh_search_runner = Searcher(
        args.gh_token,
        socks_proxy=args.socks_proxy,
        http_proxy=args.http_proxy,
        github_url=args.api_url
    )
    if args.sourcegraph:
        if args.query and args.target:
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} You cannot select an organization "
                "with a custom query!"
            )

        results = gh_search_runner.use_sourcegraph_api(
            organization=args.target,
            query=args.query
        )
    else:
        if not (args.query or args.target):
            parser.error(
                f"{Fore.RED}[-]{Style.RESET_ALL} You must select an organization "
                "or pass a custom query!."
            )
        if args.query:
            results = gh_search_runner.use_search_api(
                organization=args.target,
                query=args.query
            )
        else:
            results = gh_search_runner.use_search_api(
                organization=args.target
            )

    if results:
        gh_search_runner.present_results(results, args.output_text)


def configure_parser_general(parser):
    """Helper method to add arguments to all subarguments.

    Args:
        parser: The parser to add the arguments to.
    """
    parser.add_argument(
        "--socks-proxy", "-sp",
        help=(
            "SOCKS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format"
        ),
        required=False
    )

    parser.add_argument(
        "--http-proxy", "-p",
        help=(
            "HTTPS proxy to use for requests, in"
            f" {Fore.GREEN}HOST{Style.RESET_ALL}:{Fore.GREEN}PORT"
            f" {Style.RESET_ALL}format."
        ),
        required=False
    )

    parser.add_argument(
        "--no-color", "-nc",
        help="Removes all color from output.",
        action="store_true"
    )

