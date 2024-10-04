from gatox.workflow_graph.nodes.step import StepNode
from gatox.workflow_graph.nodes.workflow import WorkflowNode
from gatox.workflow_graph.nodes.job import JobNode
from gatox.workflow_graph.nodes.repo import RepoNode
from gatox.workflow_graph.nodes.action import ActionNode
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
from gatox.caching.cache_manager import CacheManager
from gatox.workflow_parser.utility import parse_github_path


class NodeFactory:
    """
    A factory class for creating various types of nodes and caching them.

    Attributes:
        NODE_CACHE (dict): A cache to store created nodes by their names.
    """

    NODE_CACHE = {}

    @staticmethod
    def create_repo_node(repo_wrapper: Repository):
        """
        Create a RepoNode and cache it.

        Args:
            repo_wrapper: Repository: Repository wrapper
        """
        if repo_wrapper.name in NodeFactory.NODE_CACHE:
            return NodeFactory.NODE_CACHE[repo_wrapper.name], False
        else:
            repo_node = RepoNode(repo_wrapper)
            NodeFactory.NODE_CACHE[repo_node.name] = repo_node
            return repo_node, True

    @staticmethod
    def create_job_node(job_name, ref, repo_name, workflow_path):
        """
        Create a JobNode and cache it.

        Args:
            job_name (str): The name of the job.
            ref (str): The reference (e.g., branch or tag).
            repo_name (str): The name of the repository.
            workflow_path (str): The path to the workflow file.

        Returns:
            JobNode: The created JobNode instance.
        """
        job_node = JobNode(job_name, ref, repo_name, workflow_path)

        if job_node.name in NodeFactory.NODE_CACHE:
            return NodeFactory.NODE_CACHE[job_node.name]
        else:
            NodeFactory.NODE_CACHE[job_node.name] = job_node
            return job_node

    @staticmethod
    def create_workflow_node(workflow_data: Workflow, ref, repo_name, workflow_path):
        """
        Create a WorkflowNode and cache it.

        Args:
            workflow_data: Workflow: Workflow wrapper
            ref (str): The reference (e.g., branch or tag).
            repo_name (str): The name of the repository.
            workflow_path (str): The path to the workflow file.

        Returns:
            WorkflowNode: The created WorkflowNode instance.
        """
        workflow_node = WorkflowNode(ref, repo_name, workflow_path)
        if workflow_node.name in NodeFactory.NODE_CACHE:
            NodeFactory.NODE_CACHE[workflow_node.name].initialize(workflow_data)

            return NodeFactory.NODE_CACHE[workflow_node.name]
        else:
            NodeFactory.NODE_CACHE[workflow_node.name] = workflow_node
            workflow_node.initialize(workflow_data)

        return workflow_node

    @staticmethod
    def create_called_workflow_node(callee: str, caller_ref, caller_repo):
        """ """

        if callee.startswith("./"):
            workflow_name = callee.split("/")[-1]
            workflow_path = f".github/workflows/{workflow_name}"
            repo_name = caller_repo
            ref = caller_ref
        elif "@" in callee:
            repo_name, path, ref = parse_github_path(callee)
            workflow_name = path.split("/")[-1]
            workflow_path = f".github/workflows/{workflow_name}"

        name = f"{repo_name}:{ref}:{workflow_path}"
        if name in NodeFactory.NODE_CACHE:
            return NodeFactory.NODE_CACHE[name]
        else:
            workflow_node = WorkflowNode(ref, repo_name, workflow_path)
            NodeFactory.NODE_CACHE[workflow_node.name] = workflow_node
        return workflow_node

    @staticmethod
    def create_step_node(
        step_data, ref, repo_name, workflow_path, job_name, step_number
    ):
        """
        Create a StepNode and cache it.

        Args:
            step_data (dict): The data for the step.
            ref (str): The reference (e.g., branch or tag).
            repo_name (str): The name of the repository.
            workflow_path (str): The path to the workflow file.
            job_name (str): The name of the job.
            step_number (int): The step number within the job.

        Returns:
            StepNode: The created StepNode instance.
        """
        step_node = StepNode(
            step_data, ref, repo_name, workflow_path, job_name, step_number
        )
        NodeFactory.NODE_CACHE[step_node.name] = step_node
        return step_node

    @staticmethod
    def create_action_node(action_name, ref, action_path, repo_name, params={}):
        """
        Create an ActionNode and cache it.

        Args:
            action_name (str): The name of the action.
            ref (str): The reference (e.g., branch or tag).
            action_path (str): The path to the action file.
            repo_name (str): The name of the repository.

        Returns:
            ActionNode: The created ActionNode instance.
        """ 
        name = f"{repo_name}:{ref}:{action_path}:{action_name}"
        if name in NodeFactory.NODE_CACHE:
            return NodeFactory.NODE_CACHE[name]
        else:
            action_node = ActionNode(action_name, ref, action_path, repo_name, params)
            NodeFactory.NODE_CACHE[action_node.name] = action_node
            return action_node
