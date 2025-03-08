import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from gatox.caching.cache_manager import CacheManager
from gatox.cli.output import Output
from gatox.enumerate.ingest.ingest import DataIngestor
from gatox.enumerate.organization import OrganizationEnum
from gatox.enumerate.recommender import Recommender
from gatox.enumerate.repository import RepositoryEnum
from gatox.github.api import Api
from gatox.github.gql_queries import GqlQueries
from gatox.models.organization import Organization
from gatox.models.repository import Repository
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_graph.visitors.injection_visitor import InjectionVisitor
from gatox.workflow_graph.visitors.pwn_request_visitor import PwnRequestVisitor
from gatox.workflow_graph.visitors.runner_visitor import RunnerVisitor
from gatox.workflow_graph.visitors.dispatch_toctou_visitor import DispatchTOCTOUVisitor
from gatox.workflow_graph.visitors.review_injection_visitor import (
    ReviewInjectionVisitor,
)

from gatox.enumerate.deep_dive.ingest_non_default import IngestNonDefault
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils


logger = logging.getLogger(__name__)


class Enumerator:
    """Class holding all high level logic for enumerating GitHub, whether it is
    a user's entire access, individual organizations, or repositories.
    """

    def __init__(
        self,
        pat: str,
        socks_proxy: str = None,
        http_proxy: str = None,
        skip_log: bool = False,
        github_url: str = None,
        output_json: str = None,
        ignore_workflow_run: bool = False,
        deep_dive: bool = False,
    ):
        """Initialize enumeration class with arguments sent by user.

        Args:
            pat (str): GitHub personal access token
            socks_proxy (str, optional): Proxy settings for SOCKS proxy.
            Defaults to None.
            http_proxy (str, optional): Proxy gettings for HTTP proxy.
            Defaults to None.
            skip_log (bool, optional): If set, then run logs will not be
            downloaded.
            output_json (str, optional): JSON file to output enumeration
            results.
        """
        self.api = Api(
            pat,
            socks_proxy=socks_proxy,
            http_proxy=http_proxy,
            github_url=github_url,
        )

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_log = skip_log
        self.user_perms = None
        self.github_url = github_url
        self.output_json = output_json
        self.deep_dive = deep_dive
        self.ignore_workflow_run = ignore_workflow_run

        self.repo_e = RepositoryEnum(self.api, skip_log)
        self.org_e = OrganizationEnum(self.api)

    def __setup_user_info(self):
        """Sets up user/app token information."""
        if not self.user_perms and self.api.is_app_token():
            installation_info = self.api.get_installation_repos()

            if installation_info:
                count = installation_info["total_count"]
                if count > 0:
                    Output.info(
                        f"Gato-X is using valid a GitHub App installation token!"
                    )
                    self.user_perms = {
                        "user": "Github App",
                        "scopes": [],
                        "name": "GATO-X App Mode",
                    }

                    return True
                else:
                    return False

        if not self.user_perms:
            self.user_perms = self.api.check_user()
            if not self.user_perms:
                Output.error("This token cannot be used for enumeration!")
                return False

            Output.info(
                "The authenticated user is: "
                f"{Output.bright(self.user_perms['user'])}"
            )
            if len(self.user_perms["scopes"]):
                Output.info(
                    "The GitHub Classic PAT has the following scopes: "
                    f'{Output.yellow(", ".join(self.user_perms["scopes"]))}'
                )
            else:
                Output.warn("The token has no scopes!")

        return True

    def __query_graphql_workflows(self, queries):
        """
        Query workflows using the GitHub GraphQL API.

        This method performs an IO-heavy operation by querying workflows in batches.
        It utilizes a thread pool with a maximum of 3 workers to execute the queries concurrently.

        Args:
            queries (List[Any]): A list of GraphQL query objects to be executed.

        Returns:
            None

        Raises:
            Exception: Propagates any exceptions raised during the query execution.
        """
        with ThreadPoolExecutor(max_workers=3) as executor:
            Output.info(f"Querying repositories in {len(queries)} batches!")
            futures = []
            for i, wf_query in enumerate(queries):
                futures.append(
                    executor.submit(DataIngestor.perform_query, self.api, wf_query, i)
                )
            for future in as_completed(futures):
                Output.info(
                    f"Processed {DataIngestor.check_status()}/{len(queries)} batches.",
                    end="\r",
                )
                DataIngestor.construct_workflow_cache(future.result())

    def __retrieve_missing_ymls(self, repo_name: str):
        """ """
        repo = CacheManager().is_repo_cached(repo_name)
        if not repo:
            repo_data = self.api.get_repository(repo_name)
            if repo_data:
                repo = Repository(repo_data)
                CacheManager().set_repository(repo)

                if repo:
                    workflows = self.api.retrieve_workflow_ymls(repo)

                    for workflow in workflows:
                        CacheManager().set_workflow(
                            repo, workflow.workflow_name, workflow
                        )
            else:
                Output.warn(
                    f"Unable to retrieve workflows for {Output.bright(repo_name)}! "
                    "Ensure the repository exists and the user has access."
                )

    def __enumerate_repo_only(self, repo_name: str):
        """Enumerate only a single repository. No checks for org-level
        self-hosted runners will be performed in this case.

        Args:
            repo_name (str): Repository name in {Org/Owner}/Repo format.
            large_enum (bool, optional): Whether to only download
            run logs when workflow analysis detects runners. Defaults to False.
        """
        if not self.__setup_user_info():
            return False

        repo = CacheManager().get_repository(repo_name)

        if not repo:
            repo_data = self.api.get_repository(repo_name)
            if repo_data:
                repo = Repository(repo_data)

        if repo:
            if repo.is_archived():
                Output.tabbed(
                    f"Skipping archived repository: {Output.bright(repo.name)}!"
                )
                return False

            self.repo_e.enumerate_repository(repo)
            self.repo_e.enumerate_repository_secrets(repo)
            Recommender.print_repo_secrets(
                self.user_perms["scopes"], repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms["scopes"], repo
            )

            return repo
        else:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not "
                "exist or the user does not have access."
            )

    def __finalize_caches(self, repos: list):
        """Finalizes the caches for the repositories enumerated.

        Args:
            repos (list): List of Repository objects.
        """
        for repo in repos:
            self.__retrieve_missing_ymls(repo.name)

    def validate_only(self):
        """Validates the PAT access and exits."""
        if not self.__setup_user_info():
            return False

        if "repo" not in self.user_perms["scopes"]:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            "organizations!"
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        return [
            Organization({"login": org}, self.user_perms["scopes"], True)
            for org in orgs
        ]

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.

        Returns:
            bool: False if the PAT is not valid for enumeration.
            (list, list): Tuple containing list of orgs and list of repos.
        """
        self.__setup_user_info()

        if not self.user_perms:
            return False

        if "repo" not in self.user_perms["scopes"]:
            Output.error("Self-enumeration requires the repo scope!")
            return False

        Output.info("Enumerating user owned repositories!")

        repos = self.api.get_own_repos()
        repo_wrappers = self.enumerate_repos(repos)
        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            "organizations!"
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        org_wrappers = list(map(self.enumerate_organization, orgs))

        return org_wrappers, repo_wrappers

    def enumerate_user(self, user: str):
        """Enumerate a user's repositories."""

        if not self.__setup_user_info():
            return False

        repos = self.api.get_user_repos(user)

        if not repos:
            Output.warn(
                f"Unable to query the user: {Output.bright(user)}! Ensure the "
                "user exists!"
            )
            return False

        Output.result(f"Enumerating the {Output.bright(user)} user!")

        repo_wrappers = self.enumerate_repos(repos)

        return repo_wrappers

    def enumerate_organization(self, org: str):
        """Enumerate an entire organization, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            org (str): Organization to perform enumeration on.

        Returns:
            bool: False if a failure occurred enumerating the organization.
        """

        if not self.__setup_user_info():
            return False

        details = self.api.get_organization_details(org)

        if not details:
            Output.warn(
                f"Unable to query the org: {Output.bright(org)}! Ensure the "
                "organization exists!"
            )
            return False

        organization = Organization(details, self.user_perms["scopes"])

        Output.result(f"Enumerating the {Output.bright(org)} organization!")

        if organization.org_admin_user and organization.org_admin_scopes:
            self.org_e.admin_enum(organization)

        Recommender.print_org_findings(self.user_perms["scopes"], organization)

        Output.info("Querying repository list!")
        enum_list = self.org_e.construct_repo_enum_list(organization)

        Output.info(
            f"About to enumerate "
            f"{len(enum_list)} "
            "non-archived repos within "
            f"the {organization.name} organization!"
        )

        Output.info(f"Querying and caching workflow YAML files!")
        wf_queries = GqlQueries.get_workflow_ymls(enum_list)
        self.__query_graphql_workflows(wf_queries)
        self.__finalize_caches(enum_list)

        if self.deep_dive:
            Output.inform(
                "Deep dive workflow ingestion enabled, this will slow down enumeration!"
            )
            for repo in enum_list:
                if repo.is_archived():
                    continue
                if self.skip_log and repo.is_fork():
                    continue

                cached_repo = CacheManager().get_repository(repo.name)
                if self.deep_dive and not cached_repo.is_fork():
                    IngestNonDefault.ingest(cached_repo, self.api)

            IngestNonDefault.pool_empty()
            Output.info("Deep dive ingestion complete!")

        self.process_graph()

        try:
            for repo in enum_list:
                if repo.is_archived():
                    continue
                if repo.is_fork():
                    continue

                repo = CacheManager().get_repository(repo.name)
                if repo:
                    self.repo_e.enumerate_repository(repo)
                    Recommender.print_repo_attack_recommendations(
                        self.user_perms["scopes"], repo
                    )
                    self.repo_e.enumerate_repository_secrets(repo)
                    Recommender.print_repo_secrets(
                        self.user_perms["scopes"], repo.secrets + repo.org_secrets
                    )
                    organization.set_repository(repo)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return organization

    def process_graph(self):
        """Temporarily build new enumeration functionality
        alongside the old one and then will cut over.
        """
        Output.info(
            f"Performing graph analysis on {WorkflowGraphBuilder().graph.number_of_nodes()} nodes!"
        )

        visitors = [
            (PwnRequestVisitor, "find_pwn_requests"),
            (InjectionVisitor, "find_injections"),
            (ReviewInjectionVisitor, "find_injections"),
            (DispatchTOCTOUVisitor, "find_dispatch_misconfigurations"),
        ]

        for visitor_class, visitor_method in visitors:
            visitor = visitor_class()  # Instantiate the visitor class
            visitor_func = getattr(visitor, visitor_method)  # Get the method

            if visitor_class == PwnRequestVisitor or visitor_class == InjectionVisitor:
                results = visitor_func(
                    WorkflowGraphBuilder().graph, self.api, self.ignore_workflow_run
                )
            else:
                results = visitor_func(WorkflowGraphBuilder().graph, self.api)

            if results:
                VisitorUtils.add_repo_results(results, self.api)

        if not self.skip_log:
            RunnerVisitor.find_runner_workflows(WorkflowGraphBuilder().graph)

    def enumerate_repos(self, repo_names: list):
        """Enumerate a list of repositories, each repo must be in Org/Repo name
        format.

        Args:
            repo_names (list): Repository name in {Org/Owner}/Repo format.
        """
        repo_wrappers = []
        if not self.__setup_user_info():
            return repo_wrappers

        if len(repo_names) == 0:
            Output.error("The list of repositories was empty!")
            return repo_wrappers

        Output.info(
            f"Querying and caching workflow YAML files "
            f"from {len(repo_names)} repositories!"
        )
        queries = GqlQueries.get_workflow_ymls_from_list(repo_names)
        self.__query_graphql_workflows(queries)
        for repo in repo_names:
            self.__retrieve_missing_ymls(repo)

        if self.deep_dive:
            Output.inform(
                "Performing deep dive workflow ingestion, this will be a very slow process!"
            )
            for repo in repo_names:
                repo_obj = CacheManager().get_repository(repo)
                IngestNonDefault.ingest(repo_obj, self.api)

        IngestNonDefault.pool_empty()
        self.process_graph()

        try:
            for repo in repo_names:
                repo_obj = self.__enumerate_repo_only(repo)
                if repo_obj:
                    repo_wrappers.append(repo_obj)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return repo_wrappers
