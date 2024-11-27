from gatox.attack.pwnrequest.steps.attack_step import AttackStep
from gatox.github.api import Api

from gatox.cli.output import Output


class DispatchStep(AttackStep):
    """Dispatch step, which respresents issuing a workflow dispatch
    event with a given payload.
    """

    def __init__(
        self, credential, target_workflow: str, payload: dict, target_branch: str = None
    ):
        """ """
        self.credential = credential
        self.target_workflow = target_workflow
        self.target_branch = target_branch
        self.payload = payload

    def preflight(self, api: Api):
        """Validates preconditions for executing this step."""

        # Check if branch exists
        branch_status = api.get_branch(self.target_branch)
        # Check if workflow exists on that branch
        workflow_status = api.get_workflow(self.target_workflow, self.target_branch)
        # Check if the workflow is enabled

        return True

    def execute(self, api):
        """Execute the step after validating pre-conditions."""

        api.override_credential(self.credential)

        status = api.dispatch_workflow(
            self.target_workflow, self.target_branch, self.payload
        )

        if status:
            Output.info(
                f"Dispatched {self.target_workflow} on {self.target_branch} successfully."
            )

        api.reset_credential()

    def handoff(self):
        """ """
        pass
