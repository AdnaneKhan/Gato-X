from gatox.attack.pwnrequest.steps.attack_step import AttackStep


class Merge(AttackStep):
    """Represents using a PAT or GITHUB_TOKEN with pull requests
    write and contents write to approve and merge pull request.
    """

    def preflight(self, api, previous_results=...):
        # Validate the GITHUB_TOKEN

        # Validate that the target branch does not have branch protection
        pass

    def execute(self, api):
        """Execute the step after validating pre-conditions."""

        # Create branch if it does not exist

        # Commit file

        pass

    def handoff(self):
        """Handoff the step to the next part of the attack chain."""
