"""
Copyright 2025, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from gatox.workflow_graph.nodes.step import StepNode
from gatox.workflow_graph.nodes.workflow import WorkflowNode
from gatox.workflow_graph.nodes.job import JobNode
from gatox.workflow_graph.nodes.repo import RepoNode
from gatox.workflow_graph.nodes.action import ActionNode
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
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
        Create a RepoNode for the given repository and cache it.

        This method checks if a RepoNode for the specified repository already exists
        in the cache. If it does, it returns the cached node. Otherwise, it creates
        a new RepoNode, caches it, and then returns it.

        Args:
            repo_wrapper (Repository): The repository wrapper containing repository details.

        Returns:
            tuple: A tuple containing the RepoNode instance and a boolean indicating
                   whether the node was newly created (True) or retrieved from the cache (False).
        """
        if repo_wrapper.name in NodeFactory.NODE_CACHE:
            return NodeFactory.NODE_CACHE[repo_wrapper.name], False
        else:
            repo_node = RepoNode(repo_wrapper)
            NodeFactory.NODE_CACHE[repo_node.name] = repo_node
            return repo_node, True

    @staticmethod
    def create_job_node(job_name, ref, repo_name, workflow_path, needs: list = []):
        """
        Create a JobNode for the specified job and cache it.

        This method checks if a JobNode with the given name already exists in the cache.
        If it does, it returns the cached node. Otherwise, it creates a new JobNode,
        caches it, and then returns it.

        Args:
            job_name (str): The name of the job.
            ref (str): The reference (e.g., branch or tag) associated with the job.
            repo_name (str): The name of the repository where the job resides.
            workflow_path (str): The path to the workflow file containing the job.
            needs (list, optional): A list of dependencies required by the job.

        Returns:
            JobNode: The created or cached JobNode instance.
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
        Create a WorkflowNode for the specified workflow and cache it.

        This method checks if a WorkflowNode with the given name already exists in the cache.
        If it does, it initializes the existing node with the provided workflow data.
        Otherwise, it creates a new WorkflowNode, initializes it with the workflow data,
        caches it, and then returns it.

        Args:
            workflow_data (Workflow): The workflow wrapper containing workflow details.
            ref (str): The reference (e.g., branch or tag) associated with the workflow.
            repo_name (str): The name of the repository where the workflow resides.
            workflow_path (str): The path to the workflow file.

        Returns:
            WorkflowNode: The created or initialized WorkflowNode instance.
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
        """
        Create a WorkflowNode for a called workflow and cache it.

        This method parses the callee string to determine the workflow's repository,
        path, and reference. It then checks if a WorkflowNode with the constructed name
        exists in the cache. If it does, it returns the cached node. Otherwise, it creates
        a new WorkflowNode, caches it, and then returns it.

        Args:
            callee (str): The reference to the called workflow, which could be a relative path
                          (starting with "./") or a full GitHub path with a specific ref.
            caller_ref (str): The reference (e.g., branch or tag) of the calling workflow.
            caller_repo (str): The name of the repository where the calling workflow resides.

        Returns:
            WorkflowNode: The created or cached WorkflowNode instance.
        """
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
        Create a StepNode for the specified step and cache it.

        This method creates a new StepNode with the provided data and caches it using its
        name as the key. It then returns the created StepNode instance.

        Args:
            step_data (dict): The data dictionary containing step details.
            ref (str): The reference (e.g., branch or tag) associated with the step.
            repo_name (str): The name of the repository where the step resides.
            workflow_path (str): The path to the workflow file containing the step.
            job_name (str): The name of the job that includes this step.
            step_number (int): The sequential number of the step within the job.

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
        Create an ActionNode for the specified action and cache it.

        This method constructs the name of the ActionNode using the repository name,
        reference, action path, and action name. It then checks if an ActionNode with
        this name exists in the cache. If it does, it returns the cached node.
        Otherwise, it creates a new ActionNode, caches it, and then returns it.

        Args:
            action_name (str): The name of the action.
            ref (str): The reference (e.g., branch or tag) associated with the action.
            action_path (str): The file system path to the action within the repository.
            repo_name (str): The name of the repository where the action resides.
            params (dict, optional): Additional parameters for the action.

        Returns:
            ActionNode: The created or cached ActionNode instance.
        """
        name = f"{repo_name}:{ref}:{action_path}:{action_name}"
        if name in NodeFactory.NODE_CACHE:
            return NodeFactory.NODE_CACHE[name]
        else:
            action_node = ActionNode(action_name, ref, action_path, repo_name, params)
            NodeFactory.NODE_CACHE[action_node.name] = action_node
            return action_node
