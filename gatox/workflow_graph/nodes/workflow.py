from gatox.workflow_graph.nodes.node import Node
from gatox.workflow_graph.nodes.job import JobNode
from gatox.models.workflow import Workflow


class WorkflowNode(Node):
    """Workflow node"""

    def __init__(self, ref: str, repo_name: str, workflow_path: str):
        """Constructor for workflow wrapper."""

        # Create a unique ID for this workflow.
        self.name = f"{repo_name}:{ref}:{workflow_path}"
        # By default, a workflow node is "uninitialized" until it is processed
        # with the workflow YAML. We sometimes add unititialized nodes to the
        # graph if a workflow references another workflow that has not been
        # processed yet.
        self.uninitialized = True
        self.__workflow_path = workflow_path
        self.triggers = []
        self.__callers = []
        self.repo_name = repo_name
        self.env_vars = {}
        self.inputs = {}

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def set_params(self, params):
        self.params = params

    def get_parts(self):

        repo, ref, path = self.name.split(":")

        return repo, ref, path

    def get_workflow_name(self):
        """
        Get name of the workflow file associated with the JobNode instance.

        Returns:
            str: The path to the workflow file.
        """
        return self.__workflow_path.replace(".github/workflows/", "")

    def __get_triggers(self, workflow_data: dict):
        """Retrieve the triggers associated with the Workflow node."""
        triggers = workflow_data.get("on", [])
        extracted_triggers = []

        if isinstance(triggers, list):
            return triggers
        elif isinstance(triggers, str):
            return [triggers]
        elif isinstance(triggers, dict):
            for trigger, trigger_conditions in triggers.items():
                if trigger == "pull_request_target":
                    if trigger_conditions and "types" in trigger_conditions:
                        if (
                            "labeled" in trigger_conditions["types"]
                            and len(trigger_conditions["types"]) == 1
                        ):
                            extracted_triggers.append(
                                f"{trigger}:{trigger_conditions['types'][0]}"
                            )
                        else:
                            extracted_triggers.append(trigger)
                    else:
                        extracted_triggers.append(trigger)
                else:
                    extracted_triggers.append(trigger)

        return extracted_triggers

    def __get_inputs(self, workflow_data: dict):
        try:
            if (
                "workflow_dispatch" in self.triggers
                and isinstance(workflow_data["on"], dict)
                and isinstance(workflow_data["on"]["workflow_dispatch"], dict)
                and "inputs" in workflow_data["on"]["workflow_dispatch"]
            ):
                return workflow_data["on"]["workflow_dispatch"]["inputs"]
            else:
                return {}
        except TypeError:
            print(workflow_data["on"])

    def __get_envs(self, workflow_data: dict):
        if "env" in workflow_data:
            return workflow_data["env"]
        else:
            return {}

    def add_caller_reference(self, caller: JobNode):
        """Add a reference to a JobNode that calls this Workflow node,
        if it is not already marked (as we can reach it multiple times
        for nested relationships).
        """
        if caller not in self.__callers:
            self.__callers.append(caller)

    def get_caller_workflows(self):
        """Retrieve a set of the workflows that call this Workflow node."""
        if not self.__callers:
            return set()
        else:
            return set([caller.get_workflow() for caller in self.__callers])

    def initialize(self, workflow: Workflow):
        """Initialize the Workflow node with the parsed workflow data."""
        self.triggers = self.__get_triggers(workflow.parsed_yml)

        self.env_vars = self.__get_envs(workflow.parsed_yml)

        self.inputs = self.__get_inputs(workflow.parsed_yml)
        self.uninitialized = False

    def get_tags(self):
        """ """
        tags = set([self.__class__.__name__])

        if self.uninitialized:
            tags.add("uninitialized")
        else:
            tags.add("initialized")

        for trigger in self.triggers:
            tags.add(trigger)

        return tags

    def get_attrs(self):
        """Retrieve node attributes associated with the Workflow node."""
        return {}
