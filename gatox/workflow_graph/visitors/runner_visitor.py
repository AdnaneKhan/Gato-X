from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder


class RunnerVisitor:

    @staticmethod
    def find_runner_workflows(graph: TaggedGraph):
        """Graph visitor to find workflows that are likely
        to use self-hosted runners.
        """
        nodes = graph.get_nodes_for_tags(["self-hosted"])

        workflows = {}
        for node in nodes:
            repo = node.repo_name
            workflows.setdefault(repo, []).append(node.get_workflow_path())

        return workflows
