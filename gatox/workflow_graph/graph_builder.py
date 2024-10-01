import networkx as nx

from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
from gatox.workflow_graph.node_factory import NodeFactory
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.nodes.job import JobNode


class WorkflowGraphBuilder:
    _instance = None

    def __new__(cls):
        """
        Create a new instance of the class. If an instance already exists, return that instance.
        """
        if cls._instance is None:
            cls._instance = super(WorkflowGraphBuilder, cls).__new__(cls)
            cls._instance.graph = TaggedGraph()

        return cls._instance

    def build_lone_repo_graph(self, repo_wrapper: Repository):
        """
        Build a graph node for a repository that has no workflows.
        """
        repo, added = NodeFactory.create_repo_node(repo_wrapper)
        if added:
            self.graph.add_node(repo, **repo.get_attrs())

    def add_callee_job(
        self, workflow_wrapper: Workflow, callee: str, job_def: dict, job_node: JobNode
    ):
        """
        Adds a reference to a called workflow (reusable workflow)
        """
        if not job_def or not job_node:
            return

        callee_node = NodeFactory.create_called_workflow_node(
            callee, workflow_wrapper.branch, workflow_wrapper.repo_name
        )

        if not callee_node in self.graph.nodes:
            self.graph.add_node(callee_node, **callee_node.get_attrs())
        self.graph.add_edge(job_node, callee_node, relation="uses")

    def build_graph_from_yaml(
        self, workflow_wrapper: Workflow, repo_wrapper: Repository
    ):
        """
        Build a graph from a workflow yaml file.
        """
        if workflow_wrapper.isInvalid() or not repo_wrapper:
            return

        repo, added = NodeFactory.create_repo_node(repo_wrapper)
        if added:
            self.graph.add_node(repo, **repo.get_attrs())

        workflow = workflow_wrapper.parsed_yml

        wf_node = NodeFactory.create_workflow_node(
            workflow_wrapper,
            workflow_wrapper.branch,
            workflow_wrapper.repo_name,
            workflow_wrapper.getPath(),
        )

        self.graph.add_node(wf_node, **wf_node.get_attrs())
        self.graph.add_edge(repo, wf_node, relation="contains")

        jobs = workflow.get("jobs", {})

        if not jobs:
            return

        for job_name, job_def in jobs.items():
            job_node = NodeFactory.create_job_node(
                job_name,
                workflow_wrapper.branch,
                workflow_wrapper.repo_name,
                workflow_wrapper.getPath(),
            )
            job_node.populate(job_def)
            self.graph.add_node(job_node, **job_node.get_attrs())

            # Handle called workflows
            callee = job_def.get("uses", None)
            if callee:
                self.add_callee_job(workflow_wrapper, callee, job_def, job_node)

            # Handle job dependencies
            needs = job_def.get("needs", [])
            for need in needs:
                need_node = NodeFactory.create_job_node(
                    need,
                    workflow_wrapper.branch,
                    workflow_wrapper.repo_name,
                    workflow_wrapper.getPath(),
                )
                self.graph.add_node(need_node, **need_node.get_attrs())
                self.graph.add_edge(need_node, job_node, relation="depends")

            if not needs:
                self.graph.add_edge(wf_node, job_node, relation="contains")

            # Handle steps
            steps = job_def.get("steps", [])
            prev_step_node = None
            for iter, step in enumerate(steps):
                step_node = NodeFactory.create_step_node(
                    step,
                    workflow_wrapper.branch,
                    workflow_wrapper.repo_name,
                    workflow_wrapper.getPath(),
                    job_name,
                    iter,
                )
                self.graph.add_node(step_node, **step_node.get_attrs())

                # Steps are sequential, so for reachability checks
                # the job only "contains" the first step.
                if prev_step_node:
                    self.graph.add_edge(prev_step_node, step_node, relation="next")
                else:
                    self.graph.add_edge(job_node, step_node, relation="contains")
                prev_step_node = step_node
                # Handle actions
                if "uses" in step:
                    action_name = step["uses"]
                    if "with" in step:
                        params = step["with"]
                    else:
                        params = {}
                    action_node = NodeFactory.create_action_node(
                        action_name,
                        workflow_wrapper.branch,
                        workflow_wrapper.getPath(),
                        workflow_wrapper.repo_name,
                    )
                    self.graph.add_node(action_node, **action_node.get_attrs())
                    self.graph.add_edge(step_node, action_node, relation="uses")
