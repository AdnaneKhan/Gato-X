import logging

from datetime import datetime, timedelta

from gatox.cli.output import Output
from gatox.models.execution import Repository
from gatox.models.secret import Secret
from gatox.models.runner import  Runner
from gatox.github.api import Api
from gatox.workflow_parser.workflow_parser import WorkflowParser
from gatox.caching.cache_manager import CacheManager
from gatox.notifications.send_webhook import send_slack_webhook

logger = logging.getLogger(__name__)

class RepositoryEnum():
    """Repository specific enumeration functionality.
    """

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
  

    def __perform_runlog_enumeration(self, repository: Repository, workflows: list):
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
                    wf_run['runner_name'],
                    wf_run['runner_type'],
                    wf_run['token_permissions'],
                    runner_group=wf_run['runner_group'],
                    machine_name=wf_run['machine_name'],
                    labels=wf_run['requested_labels'],
                    non_ephemeral=wf_run['non_ephemeral']
                )

                repository.add_accessible_runner(runner)
            runner_detected = True

        return runner_detected

    def __create_info_package(
            self,
            workflow_name,
            workflow_url,
            details,
            rules,
            parent_workflow=None
        ):
        """Create information package for slack webhook.
        """
        package = {
                    "workflow_name": workflow_name,
                    "workflow_url": workflow_url,
                    "details": details,
                    "environments": rules
                }
        
        if parent_workflow:
            package['parent_workflow'] = parent_workflow 
        return package
    
    @staticmethod
    def __is_within_last_day(timestamp_str, format='%Y-%m-%dT%H:%M:%SZ'):
        # Convert the timestamp string to a datetime object
        date = datetime.strptime(timestamp_str, format)

        # Get the current date and time
        now = datetime.now()

        # Calculate the date 1 days ago
        seven_days_ago = now - timedelta(days=1)

        # Return True if the date is within the last day, False otherwise
        return seven_days_ago <= date <= now

    @staticmethod
    def __parse_github_path(path):
        parts = path.split('@')
        ref = parts[1] if len(parts) > 1 else 'main'
        repo_path = parts[0].split('/')
        repo_slug = "/".join(repo_path[0:2])
        file_path = "/".join(repo_path[2:]) if len(repo_path) > 1 else ''

        return repo_slug, file_path, ref

    def __check_callees(self, parsed_yml: WorkflowParser, repository: Repository, env_rules):
        """Check callee workflows within a repository.
        """
        if parsed_yml.callees:
            for callee in parsed_yml.callees:

                if callee in self.temp_wf_cache:
                    callee_wf = self.temp_wf_cache[callee]
                else:
                    if '@' in callee:
                        slug, path, ref = RepositoryEnum.__parse_github_path(callee)
                        callee_wf = CacheManager().get_workflow(slug, f"{path}:{ref}")
                        if not callee_wf:
                            callee_wf = self.api.retrieve_repo_file(slug, path, ref)
                            if callee_wf:
                                CacheManager().set_workflow(slug, f"{path}:{ref}", callee_wf)
                    else:
                        callee_wf = CacheManager().get_workflow(repository.name, callee)
                    if not callee_wf:
                        callee_wf = self.api.retrieve_workflow_yml(repository.name, callee)
                    if callee_wf:
                        callee_wf = WorkflowParser(callee_wf)
                        self.temp_wf_cache.update({callee_wf.wf_name : callee_wf})

                if callee_wf:
                    sub_injection = callee_wf.check_injection(bypass=True)
                    if callee_wf.is_referenced():
                        workflow_url = (
                            f"https://github.com/{callee_wf.repo_name}/"
                            f"blob/{callee_wf.branch}/{callee_wf.external_path}"
                        )
                    else:
                        workflow_url = (
                            f"{repository.repo_data['html_url']}/blob/"
                            f"{repository.repo_data['default_branch']}/.github/workflows/{callee_wf.wf_name}"
                        )
                    if sub_injection:
                        sub_injection['triggers'] = parsed_yml.get_vulnerable_triggers()
                        injection_package = self.__create_info_package(
                                callee_wf.wf_name,
                                workflow_url,
                                sub_injection,
                                env_rules,
                                parent_workflow=parsed_yml.wf_name
                            )
                        repository.set_injection(injection_package)
                    sub_pwn = callee_wf.check_pwn_request(bypass=True)
                    if sub_pwn:
                        sub_pwn['triggers'] = parsed_yml.get_vulnerable_triggers()
                        pwn_package = self.__create_info_package(
                                callee_wf.wf_name,
                                workflow_url,
                                sub_pwn,
                                env_rules,
                                parent_workflow=parsed_yml.wf_name
                            )
                        repository.set_pwn_request(pwn_package)


    def __perform_yml_enumeration(self, repository: Repository):
        """Enumerates the repository using the API to extract yml files. This
        does not generate any git clone audit log events.

        Args:
            repository (Repository): Wrapped repository object.

        Returns:
            list: List of workflows that execute on sh runner, empty otherwise.
        """
        runner_wfs = []
        self.temp_wf_cache.clear()

        if CacheManager().is_repo_cached(repository.name):
            ymls = CacheManager().get_workflows(repository.name)
        else:
            ymls = self.api.retrieve_workflow_ymls(repository.name)

        for workflow in ymls:
            if workflow.isInvalid():
                Output.warn(f"Workflow {workflow.workflow_name} was invalid!")
                continue
            try:
                # if we already cached it, then retrieve.
                if workflow.workflow_name in self.temp_wf_cache:
                    parsed_yml = self.temp_wf_cache[workflow.workflow_name]
                else:
                    parsed_yml = WorkflowParser(workflow)
                    if parsed_yml.has_trigger('workflow_call'):
                        self.temp_wf_cache.update({parsed_yml.wf_name : parsed_yml})

                self_hosted_jobs = parsed_yml.self_hosted()
                wf_injection = parsed_yml.check_injection()
                pwn_reqs = parsed_yml.check_pwn_request()

                if workflow.branch:
                    workflow_url = (f"{repository.repo_data['html_url']}/blob/" 
                                   f"{parsed_yml.branch}/.github/workflows/{parsed_yml.wf_name}")
                else:
                    workflow_url = (f"{repository.repo_data['html_url']}/blob/"
                                   f"{repository.repo_data['default_branch']}/"
                                   f".github/workflows/{parsed_yml.wf_name}")

                # We aren't interested in pwn request or injection vulns in forks
                # they are likely not viable due to actions being disabled or there
                # is no impact.
                skip_checks = False
                if pwn_reqs or wf_injection:
                    if repository.is_fork():
                        skip_checks = True

                # If we have detected either pwn requests or injection, then make a 
                # single request to see if there are any protection rules, if there are
                # then we save them off. Currently a hack - push this down and use
                # a direct query.
                if (wf_injection or pwn_reqs) and 'environment:' in workflow.workflow_contents:
                    rules = self.api.get_all_environment_protection_rules(repository.name)
                    if parsed_yml.check_rules(rules):
                        # If the rules we actually use have no requirements, skip
                        rules = []
                else:
                    rules = []

                # Checks any local workflows referenced by this
                self.__check_callees(parsed_yml, repository, rules)
                
                report_packages = []
                if wf_injection and not skip_checks and not rules: 
                    report_package = self.__create_info_package(
                        parsed_yml.wf_name,
                        workflow_url,
                        wf_injection,
                        rules
                    )
                    report_packages.append(report_package)
                    repository.set_injection(report_package)
                    
                if pwn_reqs and not skip_checks:
                    report_package = self.__create_info_package(
                        parsed_yml.wf_name,
                        workflow_url,
                        pwn_reqs,
                        rules
                    )
                    report_packages.append(report_package)
                    repository.set_pwn_request(report_package)

                for report_package in report_packages:
                    # We first check the result from GQL, if the last push was within 24 hours, 
                    # then we check if the last push impacted the specific workflow.
                    if self.__is_within_last_day(repository.repo_data['pushed_at']):
                        commit_date, author = self.api.get_file_last_updated(
                            repository.name, ".github/workflows/" + parsed_yml.wf_name
                        )
                        if self.__is_within_last_day(commit_date) and '[bot]' not in author:
                            send_slack_webhook(report_package)
                
                if self_hosted_jobs:
                    runner_wfs.append(parsed_yml.wf_name)

                if self.output_yaml:
                    success = parsed_yml.output(self.output_yaml)
                    if not success:
                        logger.warning("Failed to write yml to disk!")
                
            except ValueError as parse_error:
                print(parse_error)
                Output.warn("Encountered malformed workflow!")
            except Exception as general_error:
                Output.error("Encountered a Gato-X error (likely a bug) while processing a workflow:")
                import traceback
                traceback.print_exc()
                print(f"{workflow.workflow_name}: {str(general_error)}")

        return runner_wfs

    def enumerate_repository(self, repository: Repository, large_org_enum=False):
        """Enumerate a repository, and check everything relevant to
        self-hosted runner abuse that that the user has permissions to check.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
            large_org_enum (bool, optional): Whether to only 
            perform run log enumeration if workflow analysis indicates likely
            use of a self-hosted runner. Defaults to False.
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
                        os=runner['os'],
                        status=runner['status'],
                        labels=runner['labels']
                    )
                    for runner in runners
                ]

                repository.set_runners(repo_runners)

        workflows = self.__perform_yml_enumeration(repository)

        if len(workflows) > 0:
            repository.add_self_hosted_workflows(workflows)
            runner_detected = True

        if not self.skip_log:
            # If we are enumerating an organization, only enumerate runlogs if
            # the workflow suggests a sh_runner.
            if large_org_enum and runner_detected:
                self.__perform_runlog_enumeration(repository, workflows)

            # If we are doing internal enum, get the logs, because coverage is
            # more important here and it's ok if it takes time.
            elif not repository.is_public() or not large_org_enum:
                runner_detected = self.__perform_runlog_enumeration(repository, workflows)

        if runner_detected:
            # Only display permissions (beyond having none) if runner is
            # detected.
            repository.sh_runner_access = True

    def enumerate_repository_secrets(
            self, repository: Repository):
        """Enumerate secrets accessible to a repository.

        Args:
            repository (Repository): Wrapper object created from calling the
            API and retrieving a repository.
        """
        if repository.can_push():
            secrets = self.api.get_secrets(repository.name)
            wrapped_env_secrets = []
            for environment in repository.repo_data['environments']:
                env_secrets = self.api.get_environment_secrets(repository.name, environment) 
                for secret in env_secrets:
                    wrapped_env_secrets.append(Secret(secret, repository.name, environment))

            repo_secrets = [
                Secret(secret, repository.name) for secret in secrets
            ]

            repo_secrets.extend(wrapped_env_secrets)
            repository.set_secrets(repo_secrets)

            org_secrets = self.api.get_repo_org_secrets(repository.name)
            org_secrets = [
                Secret(secret, repository.org_name)
                for secret in org_secrets
            ]

            if org_secrets:
                repository.set_accessible_org_secrets(org_secrets)