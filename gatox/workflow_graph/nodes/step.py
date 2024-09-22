from gatox.workflow_parser.utility import parse_script

from gatox.workflow_graph.nodes.node import Node


class StepNode(Node):
    """Wrapper class for a Github Actions workflow step."""

    def __init__(
        self,
        step_data: dict,
        ref: str,
        repo_name: str,
        workflow_path: str,
        job_name: str,
        step_number: int,
    ):
        """Constructor for step wrapper."""

        # Create a unique ID for this step.
        if "name" in step_data:
            self.name = f"{repo_name}:{ref}:{workflow_path}:{job_name}:{step_data['name']}_{step_number}"
        else:
            self.name = (
                f"{repo_name}:{ref}:{workflow_path}:{job_name}:step_{step_number}"
            )

        self.type = self.__get_type(step_data)
        self.is_checkout = False
        if "if" in step_data and step_data["if"]:
            self.if_condition = step_data["if"].replace("\n", "")
        else:
            self.if_condition = ""
        self.is_sink = False
        self.metadata = False

        if self.type == "script":
            self.__process_script(step_data["run"])
        elif self.type == "action":
            self.__process_action(step_data["uses"])

    def __get_type(self, step_data: dict):
        """Retrieve the type of the step."""
        if "uses" in step_data:
            return "action"
        elif "run" in step_data:
            return "script"
        else:
            return "unknown"

    def __process_script(self, script: str):
        """Process a 'run' script as part of a step."""
        if not script:
            return

        insights = parse_script(script)

        self.is_checkout = insights["is_checkout"]
        self.is_sink = insights["is_sink"]
        self.metadata = insights["metadata"]

    def __process_action(self, action: str):
        """ """

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def get_attrs(self):
        """ """
        return {
            "type": self.type,
            "is_gate": False,
            "is_checkout": self.is_checkout,
            "if_check": self.if_condition,
            "is_sink": self.is_sink,
        }
