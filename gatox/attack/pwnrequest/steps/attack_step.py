# high level class for an attack step. Will get constructed purely from the custom
# yaml step definition.


class AttackStep:
    """Base class for attack step."""

    SUCCESS_STATUS = "SUCCESS"
    FAIL_STATUS = "FAILURE"

    def __init__(self, description, step_type, step_data):
        self.description = description
        self.step_type = step_type
        self.step_data = step_data
        self.is_terminal = False
        self.next = None

    def __str__(self):
        return f"{self.__class__.__name__} - {self.step_data}"

    def sanity(self, api):
        """Checks that should be done before executing the attack at all.

        These are typically unauth checks to make sure conditions exist so that
        the step would be possible in the first place.
        """
        return True

    def setup(self, api):
        """Setup the step"""
        return True

    def preflight(self, api, previous_results: dict = {}):
        """ """
        return True

    def execute(self, api):
        """Execute the step after validating pre-conditions."""
        return True

    def isTerminal(self):
        """Check if this step is terminal."""
        return self.is_terminal

    def handoff(self):
        """ """
        return self.output
