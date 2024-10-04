from gatox.workflow_parser.utility import parse_script, getTokens, filter_tokens

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
        self.id = step_data.get("id", None)
        if "if" in step_data and step_data["if"]:
            self.if_condition = step_data["if"].replace("\n", "")
        else:
            self.if_condition = ""
        self.is_sink = False
        self.params = {}
        self.contexts = []
        self.metadata = False

        if self.type == "script":
            self.__process_script(step_data["run"])
        elif self.type == "action":
            self.__process_action(step_data)

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

        self.contexts = filter_tokens(getTokens(script))

    def __process_action(self, step_data: str):
        """ """
        uses = step_data["uses"]
        if "with" in step_data:
            self.params = step_data["with"]

        if "/checkout" in uses and "with" in step_data and "ref" in step_data["with"]:
            ref_param = step_data["with"]["ref"]
            # If the ref is not a string, it's not going to reference the PR head.
            if type(ref_param) is not str:
                self.is_checkout = False
            elif "${{" in ref_param and "base" not in ref_param:
                self.metadata = ref_param
                self.is_checkout = True
        elif (
            "github-script" in uses
            and "with" in step_data
            and "script" in step_data["with"]
        ):
            contents = step_data["with"]["script"]
            self.contexts = filter_tokens(getTokens(contents))

            if "require('." in contents:
                self.is_sink = True
        elif uses.startswith("./"):
            self.is_sink = True

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def get_tags(self):
        """ """
        tags = set([self.__class__.__name__])

        if self.is_checkout:
            tags.add("checkout")

        if self.is_sink:
            tags.add("sink")

        if self.contexts:
            tags.add("injectable")

        return tags

    def get_attrs(self):
        """ """
        attr_dict = {
            self.__class__.__name__: True,
            "type": self.type,
            "is_soft_gate": False,
            "is_hard_gate": False,
        }
        return attr_dict
