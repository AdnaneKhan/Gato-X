from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_parser.utility import CONTEXT_REGEX


class VisitorUtils:
    """
    Class to track contextual information during a single visit.
    """

    @staticmethod
    def _add_results(path, results: dict):
        """
        Add a path to the results dictionary under the corresponding repository.

        Args:
            path (List[Node]): The path of nodes representing a potential injection.
            results (dict): The dictionary aggregating results, keyed by repository name.

        Returns:
            None
        """
        repo_name = path[0].repo_name
        if repo_name not in results:
            results[repo_name] = []

        results[repo_name].append(path)

    @staticmethod
    def initialize_action_node(graph, api, node):
        """
        Initialize an action node by removing the 'uninitialized' tag and setting up the node.

        Args:
            graph (TaggedGraph): The workflow graph containing all nodes.
            api (Api): An instance of the API wrapper to interact with GitHub APIs.
            node (Node): The node to be initialized.

        Returns:
            None
        """
        tags = node.get_tags()
        if "uninitialized" in tags:
            WorkflowGraphBuilder()._initialize_action_node(node, api)
            graph.remove_tags_from_node(node, ["uninitialized"])

    @staticmethod
    def check_mutable_ref(ref, start_tags=set()):
        """
        Check if a reference is mutable based on allowed GitHub SHA references.

        Args:
            ref (str): The reference string to check.
            start_tags (set, optional): A set of starting tags for additional context. Defaults to set().

        Returns:
            bool: False if the reference matches known immutable patterns, True otherwise.
        """
        if "github.event.pull_request.head.sha" in ref:
            return False
        elif "github.event.workflow_run.head.sha" in ref:
            return False
        elif "github.sha" in ref:
            return False
        # If the trigger is pull_request_target and we have a sha in the reference, then this is very likely
        return True
