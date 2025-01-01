from gatox.workflow_graph.nodes.node import Node

from gatox.workflow_parser.utility import process_matrix, process_runner


class JobNode(Node):
    """
    Wrapper class for a GitHub Actions workflow job.

    Attributes:
        name (str): A unique identifier for the job node.
        params (dict): Parameters associated with the job node.
    """

    def __init__(self, job_name: str, ref: str, repo_name: str, workflow_path: str):
        """
        Constructor for the job wrapper.

        Args:
            job_name (str): The name of the job.
            ref (str): The reference (e.g., branch or tag).
            repo_name (str): The name of the repository.
            workflow_path (str): The path to the workflow file.
        """
        # Create a unique ID for this step.
        self.name = f"{repo_name}:{ref}:{workflow_path}:{job_name}"
        self.ref = ref
        self.workflow_path = workflow_path
        self.params = {}
        self.repo_name = repo_name
        self.if_condition = None
        self.deployments = []
        self.env_vars = {}
        self.self_hosted = False
        self.outputs = {}

    def __hash__(self):
        """
        Return the hash value of the JobNode instance.

        Returns:
            int: The hash value of the JobNode instance.
        """
        return hash((self.name, self.__class__.__name__))

    def _check_selfhosted(self, job_def: dict):
        """Returns true if the job might run on a self-hosted runner."""

        # Easy
        if "self-hosted" in job_def["runs-on"]:
            return True
        # Process a matrix job
        elif "matrix." in job_def["runs-on"]:
            return process_matrix(job_def, job_def["runs-on"])
        # Process standard label
        else:
            return process_runner(job_def["runs-on"])

    def get_workflow_path(self):
        """
        Get the path to the workflow file associated with the JobNode instance.

        Returns:
            str: The path to the workflow file.
        """
        return self.workflow_path

    def populate(self, job_def):
        if "if" in job_def:
            self.if_condition = job_def["if"].replace("\n", "")

        self.outputs = job_def.get("outputs", {})

        params = job_def.get("with", {})
        if params:
            self.set_params(params)

        if "runs-on" in job_def:
            self.self_hosted = self._check_selfhosted(job_def)

        if "environment" in job_def:
            if type(job_def["environment"]) == list:
                self.deployments.extend(job_def["environment"])
            else:
                self.deployments.append(job_def["environment"])

        if "env" in job_def:
            self.env_vars = job_def["env"]

    def __eq__(self, other):
        """
        Check if two JobNode instances are equal.

        Args:
            other (JobNode): Another JobNode instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def set_params(self, params):
        self.params = params

    def get_tags(self):
        """
        Get the tags associated with the JobNode instance.

        Returns:
            set: A set containing the class name of the JobNode instance.
        """
        tags = set([self.__class__.__name__])

        if self.self_hosted:
            tags.add("self-hosted")

        return tags

    def get_attrs(self):
        """
        Get the attributes associated with the JobNode instance.

        Returns:
            dict: A dictionary containing attributes of the JobNode instance.
        """
        attr_dict = {
            self.__class__.__name__: True,
            "is_soft_gate": False,
            "is_hard_gate": False,
        }
        return attr_dict
