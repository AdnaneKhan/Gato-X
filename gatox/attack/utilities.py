import random
import string
import time

from gatox.cli.output import Output


class AttackUtilities:
    """
    Utility class for attack related functions.
    """

    @staticmethod
    def create_gist(api, gist_contents: str):
        """Create a Gist with the specified contents and return the raw URL."""

        exfil_name = "".join(random.choices(string.ascii_lowercase, k=5))

        gist_params = {"files": {f"{exfil_name}": {"content": gist_contents}}}

        result = api.call_post("/gists", params=gist_params)

        if result.status_code == 201:
            return result.json()["id"]

    @staticmethod
    def fork_and_check_repository(api, target_repo, timeout):
        """Utility function to fork a repository and check if it exists."""
        repo_name = api.fork_repository(target_repo)
        if not repo_name:
            Output.error("Error while forking repository!")
            return False

        for i in range(timeout):
            status = api.get_repository(repo_name)
            if status:
                Output.result(f"Successfully created fork: {repo_name}!")
                time.sleep(5)
                return repo_name
            else:
                time.sleep(1)

        Output.error(f"Forked repository not found after {timeout} seconds!")
        return False
