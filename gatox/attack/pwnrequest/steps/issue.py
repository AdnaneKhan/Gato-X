from gatox.attack.attack import AttackStep


class IssueStep(AttackStep):
    """Issue step, which represents issuing a workflow dispatch
    event with a given payload.
    """

    def __init__(self):
        """ """

    def preflight(self):
        """Validates preconditions for executing this step."""
        return True

    def execute(self, api):
        """Execute the step after validating pre-conditions."""

        # api.create_issue(target_repo, title, body)

        pass
