from gatox.workflow_graph.nodes.node import Node


class JobNode(Node):
    """Wrapper class for a Github Actions worflow job."""

    def __init__(self, job_name: str, ref: str, repo_name: str, workflow_path: str):
        """Constructor for job wrapper."""

        # Create a unique ID for this step.
        self.name = f"{repo_name}:{ref}:{workflow_path}:{job_name}"

    def __hash__(self):
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.name == other.name

    def get_attrs(self):
        """ 
        """

        attr_dict = {
            self.__class__.__name__: True,
            "type": self.type,
            "is_soft_gate": False,
            "is_hard_gate": False
        }

        return attr_dict