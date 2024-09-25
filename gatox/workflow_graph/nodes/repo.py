from gatox.workflow_graph.nodes.node import Node
from gatox.models.repository import Repository


class RepoNode(Node):
    """Wrapper class for a GitHub repository."""

    def __init__(self, repo_wrapper: Repository):
        """Constructor for repo wrapper."""

        # Create a unique ID for this step.
        self.name = f"{repo_wrapper.name}"

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def get_attrs(self):
        """ 
        """
        return {
            self.__class__.__name__: True,
        } 