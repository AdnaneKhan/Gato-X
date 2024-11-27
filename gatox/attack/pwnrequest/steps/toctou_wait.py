from gatox.attack.pwnrequest.steps.attack_step import AttackStep


class TocTouWait(AttackStep):
    """Step to wait for a trigger condition.

    The poll interval here is only fast enough to win actions race conditions,
    e.g. issue comment, pull request target label. It will not be fast enough
    to win race conditions resulting from webhook integrations with third party
    services such as Azure Pipelines or BuildKite.
    """

    WAIT_TYPES = ["COMMENT", "LABEL", "ENVIRONMENT"]

    def __init__(self):
        pass

    def execute(self, api):
        """Execute the step after validating pre-conditions."""
        pass

    def wait(self, api):
        """ """
        pass
