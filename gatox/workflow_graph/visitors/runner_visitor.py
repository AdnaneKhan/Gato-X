import logging

from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder

logger = logging.getLogger(__name__)


class RunnerVisitor:
    """Simple visitor that extracts nodes that are tagged to potentially
    run on self-hosted runners.
    """

    @staticmethod
    def find_runner_workflows(graph: TaggedGraph):
        """Graph visitor to find workflows that are likely
        to use self-hosted runners.
        """
        nodes = graph.get_nodes_for_tags(["self-hosted"])

        workflows = {}
        for node in nodes:
            try:
                repo = node.repo_name()

                if "workflow_call" in node.get_workflow().get_tags():
                    # We need to find the parent workflow.
                    callers = node.get_workflow().get_caller_workflows()
                    for caller in callers:
                        workflows.setdefault(repo, set()).add(
                            caller.get_workflow_name()
                        )

                workflows.setdefault(repo, set()).add(node.get_workflow_name())
            except Exception as e:
                logger.warning(f"Error processing node: {node.name}")
                logger.warning(e)

        return workflows
