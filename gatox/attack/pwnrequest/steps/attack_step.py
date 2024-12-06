# high level class for an attack step. Will get constructed purely from the custom
# yaml step definition.

import functools


class AttackStep:
    """Base class for attack step."""

    SUCCESS_STATUS = "SUCCESS"
    FAIL_STATUS = "FAILURE"

    @staticmethod
    def require_params(*required_params):
        """
        Decorator to ensure that all required parameters are present.

        Args:
            *required_params: Arbitrary number of required parameter names.

        Raises:
            ValueError: If any required parameters are missing.
        """

        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Check for missing required parameters
                missing = [p for p in required_params if p not in kwargs]
                if missing:
                    raise ValueError(
                        f"Missing required parameters: {', '.join(missing)}"
                    )
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def __init__(self, description, step_type, step_data):
        self.description = description
        self.step_type = step_type
        self.step_data = step_data
        self.is_terminal = False
        self.next = None
        self.output = {}

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

    def preflight(self, api, previous_results=...):
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
