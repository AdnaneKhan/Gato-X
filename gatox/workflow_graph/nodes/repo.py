from gatox.workflow_graph.nodes.node import Node
from gatox.models.repository import Repository


class RepoNode(Node):
    """
    Wrapper class for a GitHub repository.

    Attributes:
        name (str): A unique identifier for the repository node.
    """

    def __init__(self, repo_wrapper: Repository):
        """
        Constructor for the repository wrapper.

        Args:
            repo_wrapper (Repository): The repository object to wrap.
        """
        # Create a unique ID for this repository.
        self.name = f"{repo_wrapper.name}"

    def __hash__(self):
        """
        Return the hash value of the RepoNode instance.

        Returns:
            int: The hash value of the RepoNode instance.
        """
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        """
        Check if two RepoNode instances are equal.

        Args:
            other (RepoNode): Another RepoNode instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def get_tags(self):
        """
        Get the tags associated with the RepoNode instance.

        Returns:
            set: A set containing the class name of the RepoNode instance.
        """
        tags = set([self.__class__.__name__])
        return tags

    def get_attrs(self):
        """
        Retrieve attributes associated with the RepoNode instance.

        Returns:
            dict: A dictionary containing attributes of the RepoNode instance.
        """
        return {
            self.__class__.__name__: True,
        }