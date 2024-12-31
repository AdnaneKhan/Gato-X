from gatox.workflow_parser.utility import parse_script, getTokens, filter_tokens
from gatox.workflow_graph.nodes.node import Node


class StepNode(Node):
    """
    Wrapper class for a GitHub Actions workflow step.

    Attributes:
        name (str): A unique identifier for the step node.
        type (str): The type of the step (script, action, or unknown).
        is_checkout (bool): Indicates if the step is a checkout step.
        id (str): The ID of the step.
        if_condition (str): The condition under which the step runs.
        is_sink (bool): Indicates if the step is a sink.
        hard_gate (bool): Indicates if the step is a hard gate.
        soft_gate (bool): Indicates if the step is a soft gate.
        params (dict): Parameters associated with the step.
        contexts (list): List of contexts associated with the step.
        metadata (bool): Metadata associated with the step.
        outputs (dict): Outputs of the step.
    """

    def __init__(
        self,
        step_data: dict,
        ref: str,
        repo_name: str,
        workflow_path: str,
        job_name: str,
        step_number: int,
    ):
        """
        Constructor for the step wrapper.

        Args:
            step_data (dict): The data for the step.
            ref (str): The reference (e.g., branch or tag).
            repo_name (str): The name of the repository.
            workflow_path (str): The path to the workflow file.
            job_name (str): The name of the job.
            step_number (int): The step number within the job.
        """
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
        self.if_condition = step_data.get("if", "").replace("\n", "")
        self.is_sink = False
        self.hard_gate = False
        self.soft_gate = False
        self.params = {}
        self.contexts = []
        self.metadata = False
        self.outputs = step_data.get("outputs", {})

        if self.type == "script":
            self.__process_script(step_data["run"])
        elif self.type == "action":
            self.__process_action(step_data)

    def __get_type(self, step_data: dict):
        """
        Retrieve the type of the step.

        Args:
            step_data (dict): The data for the step.

        Returns:
            str: The type of the step (script, action, or unknown).
        """
        if "uses" in step_data:
            return "action"
        elif "run" in step_data:
            return "script"
        else:
            return "unknown"

    def __process_script(self, script: str):
        """
        Process a 'run' script as part of a step.

        Args:
            script (str): The script to process.
        """
        if not script:
            return

        insights = parse_script(script)

        self.is_checkout = insights["is_checkout"]
        self.is_sink = insights["is_sink"]
        self.metadata = insights["metadata"]
        self.hard_gate = insights["hard_gate"]
        self.soft_gate = insights["soft_gate"]

        self.contexts = filter_tokens(getTokens(script))

    def __process_action(self, step_data: dict):
        """
        Process an 'action' step.

        Args:
            step_data (dict): The data for the step.
        """
        uses = step_data["uses"]
        self.params = step_data.get("with", {})

        if "/checkout" in uses and "ref" in self.params:
            ref_param = self.params["ref"]
            if isinstance(ref_param, str):
                if "${{" in ref_param and "base" not in ref_param:
                    if (
                        "github.event.pull_request.head.ref" in ref_param
                        or "github.head_ref" in ref_param
                        and "repo" not in self.params
                    ):
                        self.is_checkout = False
                    else:
                        self.metadata = ref_param
                        self.is_checkout = True
        elif "github-script" in uses and "script" in self.params:
            contents = self.params["script"]
            self.contexts = filter_tokens(getTokens(contents))

            insights = parse_script(contents)

            self.is_checkout = insights["is_checkout"]
            self.is_sink = insights["is_sink"]
            self.metadata = insights["metadata"]
            self.hard_gate = insights["hard_gate"]
            self.soft_gate = insights["soft_gate"]

            if "require('." in contents:
                self.is_sink = True
        elif uses.startswith("./"):
            self.is_sink = True
        elif "ruby/setup-ruby" in uses:
            self.is_sink = self.params.get("bundler-cache", False)
        elif "actions/setup-node" in uses:
            self.is_sink = self.params.get("cache", False)

    def __hash__(self):
        """
        Return the hash value of the StepNode instance.

        Returns:
            int: The hash value of the StepNode instance.
        """
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        """
        Check if two StepNode instances are equal.

        Args:
            other (StepNode): Another StepNode instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def get_tags(self):
        """
        Get the tags associated with the StepNode instance.

        Returns:
            set: A set containing the class name of the StepNode instance and additional tags.
        """
        tags = set([self.__class__.__name__])

        if self.is_checkout:
            tags.add("checkout")

        if self.is_sink:
            tags.add("sink")

        if self.contexts:
            tags.add("injectable")

        if self.hard_gate:
            tags.add("permission_blocker")

        if self.soft_gate:
            tags.add("permission_check")

        return tags

    def get_attrs(self):
        """
        Get the attributes associated with the StepNode instance.

        Returns:
            dict: A dictionary containing attributes of the StepNode instance.
        """
        return {
            self.__class__.__name__: True,
            "type": self.type,
            "is_soft_gate": self.soft_gate,
            "is_hard_gate": self.hard_gate,
        }
