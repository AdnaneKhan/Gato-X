import logging
import pickle
import os

from gato.github import Api
from gato.github import GqlQueries
from gato.models import Repository, Organization
from gato.cli import Output
from gato.enumerate.repository import RepositoryEnum
from gato.enumerate.organization import OrganizationEnum
from gato.enumerate.recommender import Recommender
from gato.caching import CacheManager

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
        output_yaml: str = None,
        skip_log: bool = False,
        github_url: str = None,
        output_json: str = None
    ):
        """Initialize enumeration class with arguments sent by user.

        Args:
            pat (str): GitHub personal access token
            socks_proxy (str, optional): Proxy settings for SOCKS proxy.
            Defaults to None.
            http_proxy (str, optional): Proxy gettings for HTTP proxy.
            Defaults to None.
            output_yaml (str, optional): If set, directory to save all yml
            files to . Defaults to None.
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

        # # Handle cache manager
        # # Unpickle the CacheManager instance
        # if os.path.exists('cache_manager.pkl'):
        #     with open('cache_manager.pkl', 'rb') as f:
        #         cache_manager = pickle.load(f)

        self.socks_proxy = socks_proxy
        self.http_proxy = http_proxy
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.user_perms = None
        self.github_url = github_url
        self.output_json = output_json

        self.repo_e = RepositoryEnum(self.api, skip_log, output_yaml)
        self.org_e = OrganizationEnum(self.api)

    # def __del__(self):
    #     """
    #     Serialize the CacheManager instance"""
    #     with open('cache_manager.pkl', 'wb') as f:
    #         pickle.dump(CacheManager(), f)

    def __setup_user_info(self):
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

    def validate_only(self):
        """Validates the PAT access and exits.
        """
        if not self.__setup_user_info():
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.warn("Token does not have sufficient access to list orgs!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        return [Organization({'login': org}, self.user_perms['scopes'], True) for org in orgs]

    def self_enumeration(self):
        """Enumerates all organizations associated with the authenticated user.

        Returns:
            bool: False if the PAT is not valid for enumeration.
        """

        self.__setup_user_info()

        if not self.user_perms:
            return False

        if 'repo' not in self.user_perms['scopes']:
            Output.error("Self-enumeration requires the repo scope!")
            return False

        orgs = self.api.check_organizations()

        Output.info(
            f'The user { self.user_perms["user"] } belongs to {len(orgs)} '
            'organizations!'
        )

        for org in orgs:
            Output.tabbed(f"{Output.bright(org)}")

        org_wrappers = list(map(self.enumerate_organization, orgs))

        return org_wrappers

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
                "organization exists!")
            return False

        organization = Organization(details, self.user_perms['scopes'])

        Output.result(f"Enumerating the {Output.bright(org)} organization!")

        if organization.org_admin_user and organization.org_admin_scopes:
            self.org_e.admin_enum(organization)

        Recommender.print_org_findings(
            self.user_perms['scopes'], organization
        )

        enum_list = self.org_e.construct_repo_enum_list(organization)

        Output.info(
            f"About to enumerate "
            f"{len(organization.private_repos) + len(organization.public_repos)}"
            " repos within "
            f"the {organization.name} organization!"
        )

        Output.info(f"Querying and caching workflow YAML files!")
        wf_queries = GqlQueries.get_workflow_ymls(enum_list)

        for i, wf_query in enumerate(wf_queries):
            Output.info(f"Querying {i} out of {len(wf_queries)} batches!")
            result = self.org_e.api.call_post('/graphql', wf_query)
            # Sometimes we don't get a 200, fall back in this case.
            if result.status_code == 200:
                self.repo_e.construct_workflow_cache(result.json()['data']['nodes'])
            else:
                Output.warn("GraphQL query failed, will revert to REST workflow query for impacted repositories!")
        try:
            for repo in enum_list:
                if repo.is_archived():
                    continue
                if self.skip_log and repo.is_fork():
                    continue
                Output.tabbed(
                    f"Enumerating: {Output.bright(repo.name)}!"
                )
                self.repo_e.enumerate_repository(repo, large_org_enum=len(enum_list) > 25)
                self.repo_e.enumerate_repository_secrets(repo)

                Recommender.print_repo_secrets(
                    self.user_perms['scopes'],
                    repo.secrets
                )
                Recommender.print_repo_runner_info(repo)

                # Only print info about individual repos if user is admin OR
                # we detect a runner.
                if repo.is_admin() or repo.sh_runner_access:
                    Recommender.print_repo_attack_recommendations(
                        self.user_perms['scopes'], repo
                    )
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return organization

    def enumerate_repo_only(self, repo_name: str, large_enum=False):
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
            Output.tabbed(
                f"Enumerating: {Output.bright(repo.name)}!"
            )
            self.repo_e.enumerate_repository(repo, large_org_enum=large_enum)
            self.repo_e.enumerate_repository_secrets(repo)
            Recommender.print_repo_secrets(
                self.user_perms['scopes'],
                repo.secrets + repo.org_secrets
            )
            Recommender.print_repo_runner_info(repo)
            Recommender.print_repo_attack_recommendations(
                self.user_perms['scopes'], repo
            )

            return repo
        else:
            Output.warn(
                f"Unable to enumerate {Output.bright(repo_name)}! It may not "
                "exist or the user does not have access."
            )

    def enumerate_repos(self, repo_names: list):
        """Enumerate a list of repositories, each repo must be in Org/Repo name
        format.

        Args:
            repo_names (list): Repository name in {Org/Owner}/Repo format.
        """
        if not self.__setup_user_info():
            return False

        if len(repo_names) == 0:
            Output.error("The list of repositories was empty!")
            return

        Output.info(f"Querying and caching workflow YAML files from {len(repo_names)} repositories!")
        queries = GqlQueries.get_workflow_ymls_from_list(repo_names)

        for i, wf_query in enumerate(queries):
            Output.info(f"Querying {i} out of {len(queries)} batches!")
            try:
                result = self.repo_e.api.call_post('/graphql', wf_query)
                if result.status_code == 200:
                    self.repo_e.construct_workflow_cache(result.json()['data'].values())
                else:
                    Output.warn("GraphQL query failed, will revert to REST workflow query for impacted repositories!")
            except Exception as e:
                print(e)
                Output.warn("GraphQL query failed, will revert to REST workflow query for impacted repositories!")

        repo_wrappers = []
        try:
            for repo in repo_names:
                repo_obj = self.enumerate_repo_only(repo, len(repo_names) > 100)
                if repo_obj:
                    repo_wrappers.append(repo_obj)
        except KeyboardInterrupt:
            Output.warn("Keyboard interrupt detected, exiting enumeration!")

        return repo_wrappers
