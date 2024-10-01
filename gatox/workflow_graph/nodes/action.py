from gatox.workflow_graph.nodes.node import Node


class ActionNode(Node):
    """
    Wrapper class for a GitHub Actions workflow action.

    Attributes:
        name (str): A unique identifier for the action node.
        params (dict): Parameters associated with the action node.
        is_sink (bool): Indicates if the action is a sink.
        is_checkout (bool): Indicates if the action is a checkout.
        if_condition (str): The condition under which the action runs.
        is_gate (bool): Indicates if the action is a gate.
        metadata (bool): Metadata associated with the action.
        initialized (bool): Indicates if the action is initialized.
        type (str): The type of the action.
    """

    def __init__(
        self, action_name: str, ref: str, action_path: str, repo_name: str, params: dict
    ):
        """
        Constructor for the action wrapper.

        Args:
            action_name (str): The name of the action.
            ref (str): The reference (e.g., branch or tag).
            action_path (str): The path to the action file.
            repo_name (str): The name of the repository.
            params (dict): Parameters associated with the action.
        """
        # Create a unique ID for this action.
        self.name = f"{repo_name}:{ref}:{action_path}:{action_name}"
        self.is_sink = False
        self.is_checkout = False
        self.if_condition = ""
        self.is_gate = False
        self.metadata = False
        self.initialized = False
        self.type = "UNK"



    def __hash__(self):
        """
        Return the hash value of the ActionNode instance.

        Returns:
            int: The hash value of the ActionNode instance.
        """
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        """
        Check if two ActionNode instances are equal.

        Args:
            other (ActionNode): Another ActionNode instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def get_tags(self):
        """
        Get the tags associated with the ActionNode instance.

        Returns:
            set: A set containing the class name of the ActionNode instance.
        """
        tags = set([self.__class__.__name__])

        if self.is_checkout:
            tags.add("checkout")

        if self.is_sink:
            tags.add("sink")

        return tags

    def get_attrs(self):
        """
        Get the attributes associated with the ActionNode instance.

        Returns:
            dict: A dictionary containing attributes of the ActionNode instance.
        """
        return {
            self.__class__.__name__: True,
            "type": self.type,
            "is_soft_gate": False,
            "is_hard_gate": False,
            "initialized": self.initialized,
        }
