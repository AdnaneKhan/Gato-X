import logging

from datetime import datetime, timedelta

from gatox.cli.output import Output
from gatox.models.execution import Repository
from gatox.models.secret import Secret
from gatox.models.runner import Runner
from gatox.github.api import Api
from gatox.notifications.send_webhook import send_slack_webhook

logger = logging.getLogger(__name__)


class RepositoryEnum:
    """Repository specific enumeration functionality."""

    def __init__(self, api: Api, skip_log: bool, output_yaml):
        """Initialize enumeration class with instantiated API wrapper and CLI
        parameters.

        Args:
            api (Api): GitHub API wraper object.
        """
        self.api = api
        self.skip_log = skip_log
        self.output_yaml = output_yaml
        self.temp_wf_cache = {}

    def perform_runlog_enumeration(self, repository: Repository, workflows: list):
        """Enumerate for the presence of a self-hosted runner based on
        downloading historical runlogs.

        Args:
            repository (Repository): Wrapped repository object.
            workflows (list): List of workflows that execute on self-hosted runner.

        Returns:
            bool: True if a self-hosted runner was detected.
        """
        runner_detected = False
        wf_runs = []

        wf_runs = self.api.retrieve_run_logs(
            repository.name, short_circuit=True, workflows=workflows
        )

        if wf_runs:
            for wf_run in wf_runs:
                runner = Runner(
                    wf_run["runner_name"],
                    wf_run["runner_type"],
                    wf_run["token_permissions"],
                    runner_group=wf_run["runner_group"],
                    machine_name=wf_run["machine_name"],
                    labels=wf_run["requested_labels"],
                    non_ephemeral=wf_run["non_ephemeral"],
                )

                repository.add_accessible_runner(runner)
            runner_detected = True

        return runner_detected

    def __create_info_package(
        self, workflow_name, workflow_url, details, rules, parent_workflow=None
    ):
        """Create information package for slack webhook."""
        package = {
            "workflow_name": workflow_name,
            "workflow_url": workflow_url,
            "details": details,
            "environments": rules,
        }

        if parent_workflow:
            package["parent_workflow"] = parent_workflow
        return package

    @staticmethod
    def __is_within_last_day(timestamp_str, format="%Y-%m-%dT%H:%M:%SZ"):
        # Convert the timestamp string to a datetime object
        date = datetime.strptime(timestamp_str, format)

        # Get the current date and time
        now = datetime.now()
        # Calculate the date 1 days ago
        one_day_ago = now - timedelta(days=1)

        # Return True if the date is within the last day, False otherwise
        return one_day_ago <= date <= now

    @staticmethod
    def __return_recent(time1, time2, format="%Y-%m-%dT%H:%M:%SZ"):
        """
        Takes two timestamp strings and returns the most recent one.

        Args:
            time1 (str): The first timestamp string.
            time2 (str): The second timestamp string.
            format (str): The format of the timestamp strings. Default is '%Y-%m-%dT%H:%M:%SZ'.

        Returns:
            str: The most recent timestamp string.
        """
        # Convert the timestamp strings to datetime objects
        date1 = datetime.strptime(time1, format)
        date2 = datetime.strptime(time2, format)

        # Return the most recent timestamp string
        return time1 if date1 > date2 else time2

    def enumerate_repository(self, repository: Repository):
        """Enumerate a repository, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
        """
        runner_detected = False
        repository.update_time()

        if not repository.can_pull():
            Output.error("The user cannot pull, skipping.")
            return

        if repository.is_admin():
            runners = self.api.get_repo_runners(repository.name)

            if runners:
                repo_runners = [
                    Runner(
                        runner,
                        machine_name=None,
                        os=runner["os"],
                        status=runner["status"],
                        labels=runner["labels"],
                    )
                    for runner in runners
                ]

                repository.set_runners(repo_runners)

    def enumerate_repository_secrets(self, repository: Repository):
        """Enumerate secrets accessible to a repository.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
        """
        if repository.can_push():
            secrets = self.api.get_secrets(repository.name)
            wrapped_env_secrets = []
            for environment in repository.repo_data["environments"]:
                env_secrets = self.api.get_environment_secrets(
                    repository.name, environment
                )
                for secret in env_secrets:
                    wrapped_env_secrets.append(
                        Secret(secret, repository.name, environment)
                    )

            repo_secrets = [Secret(secret, repository.name) for secret in secrets]

            repo_secrets.extend(wrapped_env_secrets)
            repository.set_secrets(repo_secrets)

            org_secrets = self.api.get_repo_org_secrets(repository.name)
            org_secrets = [
                Secret(secret, repository.org_name) for secret in org_secrets
            ]

            if org_secrets:
                repository.set_accessible_org_secrets(org_secrets)
