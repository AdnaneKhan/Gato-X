# high level class for an attack step. Will get constructed purely from the custom
# yaml step definition.


class AttackStep:
    """ """

    def __init__(self, description, step_type, step_data):
        self.description = description
        self.step_type = step_type
        self.step_data = step_data
        self.is_terminal = False
        self.next = None

    def __str__(self):
        return f"{self.__class__.__name__} - {self.step_data}"

    def preflight(self, api, previous_results: dict = {}):
        """ """
        pass

    def execute(self, api):
        """Execute the step after validating pre-conditions."""
        pass

    def isTerminal(self):
        """Check if this step is terminal."""
        return self.is_terminal

    def handoff(self):
        """ """
        return self.output
