import random
import string

from gatox.cli.output import Output


def AttackUtilities():
    """ """

    @staticmethod
    def create_gist(self, gist_name: str, gist_contents: str):
        """Create a Gist with the specified contents and return the raw URL."""
        self.__setup_user_info()

        if "gist" not in self.user_perms["scopes"]:
            Output.error("Unable to create Gist without gist scope!")
            return False

        exfil_name = "".join(random.choices(string.ascii_lowercase, k=5))
        gist_params = {
            "files": {f"{gist_name}-{exfil_name}": {{"content": gist_contents}}}
        }

        result = self.api.call_post("/gists", params=gist_params)

        if result.status_code == 201:
            return result["files"][f"{gist_name}-{exfil_name}"]["raw_url"]
