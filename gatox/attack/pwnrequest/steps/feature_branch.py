from gatox.attack.pwnrequest.steps.attack_step import AttackStep


class FeatureBranch(AttackStep):
    """Represents using a PAT or GITHUB_TOKEN with contents
    write access to create a feature branch and commit changes to it.
    """

    def execute(self, api):
        """Execute the step after validating pre-conditions."""
        pass

    def handoff(self):
        """Handoff the step to the next part of the attack chain."""
