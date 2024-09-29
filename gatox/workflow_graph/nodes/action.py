from gatox.workflow_graph.nodes.node import Node


class ActionNode(Node):

    def __init__(
        self, action_name: str, ref: str, action_path: str, repo_name: str, params: dict
    ):
        """Constructor for step wrapper."""

        # Create a unique ID for this step.
        self.name = f"{repo_name}:{ref}:{action_path}:{action_name}"

        self.params = params
        self.is_sink = False
        self.is_checkout = False
        self.if_condition = ""
        self.is_gate = False
        self.metadata = False
        self.initialized = False
        self.type = "UNK"

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def get_attrs(self):
        """ 
        """
        return {
            self.__class__.__name__: True,
            "type": self.type,
            "is_soft_gate": False,
            "is_hard_gate": False,
            "is_checkout": self.is_checkout,
            "if_check": self.if_condition,
            "is_sink": self.is_sink,
            "initialized": self.initialized,
        }
