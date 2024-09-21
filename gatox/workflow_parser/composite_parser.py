import yaml
from yaml import CSafeLoader

from gatox.workflow_parser.components.step import Step
from gatox.workflow_parser.utility import filter_tokens


class CompositeParser:
    """
    A class to parse and analyze composite GitHub Actions.
    """

    def __init__(self, action_yml: str):
        """
        Initializes the CompositeParser instance by loading and parsing the provided YAML file.

        Args:
            action_yml (str): The YAML file to parse.
        """
        self.parsed_yml = yaml.load(action_yml.replace("\t", "  "), Loader=CSafeLoader)
        self.steps = []
        self.name = None

        if "name" in self.parsed_yml:
            self.name = self.parsed_yml["name"]

        if self.is_composite():
            self.steps = [
                Step(step_data)
                for step_data in self.parsed_yml["runs"].get("steps", [])
            ]

    def is_composite(self):
        """
        Checks if the parsed YAML file represents a composite GitHub Actions workflow.

        Returns:
            bool: True if the parsed YAML file represents a composite GitHub
            Actions workflow, False otherwise.
        """
        if "runs" in self.parsed_yml and "using" in self.parsed_yml["runs"]:
            return self.parsed_yml["runs"]["using"] == "composite"

    def check_injection(self):
        """
        Checks if the composite action contains any unsafe context expressions.

        Returns:
            list: A list of steps that contain unsafe context expressions.
        """
        step_risk = []
        if not self.is_composite():
            return []
        for step in self.steps:

            if step.type == "RUN":
                tokens = step.getTokens()
                tokens = filter_tokens(tokens, strict=True)

                if tokens:
                    step_risk.append({f"Composite-{step.name}": tokens})

        return step_risk

    def check_pwn_request(self):
        """Checks if the composable action checks out the PR code."""
        has_checkout = False
        has_sink = False

        for step in self.steps:
            if step.is_checkout:
                has_checkout = True
            elif step.is_sink:
                has_sink = True

        if has_checkout:
            return True
