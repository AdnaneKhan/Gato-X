from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.workflow_parser.utility import CONTEXT_REGEX


class VisitorUtils:
    """Class to track contextual information during a single visit."""

    @staticmethod
    def _add_results(path, results: dict):
        """
        Add a path to the results dictionary under the corresponding repository.

        Args:
            path (List[Node]):
                The sequence of nodes representing a potential security path.
            results (dict):
                A dictionary aggregating results, keyed by repository name.

        Returns:
            None

        Raises:
            None
        """
        repo_name = path[0].repo_name
        if repo_name not in results:
            results[repo_name] = []

        results[repo_name].append(path)

    @staticmethod
    def initialize_action_node(graph, api, node):
        """
        Initialize an action node by removing the 'uninitialized' tag and setting it up.

        Args:
            graph (TaggedGraph):
                The workflow graph containing all nodes.
            api (Api):
                An instance of the API wrapper to interact with external services.
            node (Node):
                The node to be initialized.

        Returns:
            None

        Raises:
            None
        """
        tags = node.get_tags()
        if "uninitialized" in tags:
            WorkflowGraphBuilder()._initialize_action_node(node, api)
            graph.remove_tags_from_node(node, ["uninitialized"])

    @staticmethod
    def check_mutable_ref(ref, start_tags=set()):
        """
        Check if a reference is mutable based on allowed GitHub SHA patterns.

        Args:
            ref (str):
                The reference string to check.
            start_tags (set, optional):
                A set of starting tags for additional context. Defaults to an empty set.

        Returns:
            bool:
                False if the reference is immutable, True otherwise.
        """
        if "github.event.pull_request.head.sha" in ref:
            return False
        elif "github.event.workflow_run.head.sha" in ref:
            return False
        elif "github.sha" in ref:
            return False
        # If the trigger is pull_request_target and we have a sha in the reference, then this is very likely
        # to be from the original trigger in some form and not a mutable reference, so if it is gated we can suppress.
        elif "sha" in ref and "pull_request_target" in start_tags:
            return False
        # This points to the base branch, so it is not going to be exploitable.
        elif "github.ref" in ref and "||" not in ref:
            return False

        return True

    @staticmethod
    def process_context_var(value):
        """
        Process a context variable by extracting relevant parts.

        Args:
            value (str):
                The context variable string to process.

        Returns:
            str:
                The processed variable.
        """
        processed_var = value
        if "${{" in value:
            processed_var = CONTEXT_REGEX.findall(value)
            if processed_var:
                processed_var = processed_var[0]
                if "inputs." in processed_var:
                    processed_var = processed_var.replace("inputs.", "")
            else:
                processed_var = value
        else:
            processed_var = value
        return processed_var

    @staticmethod
    def append_path(head, tail):
        """
        Append the tail to the head if the tail starts with the last element of the head.

        Args:
            head (list):
                The initial path list.
            tail (list):
                The path to append.

        Returns:
            list:
                The combined path if conditions are met; otherwise, the original head.
        """
        if head and tail and head[-1] == tail[0]:
            head.extend(tail[1:])
        return head

    @staticmethod
    def ascii_render(data: dict):
        """
        Render the structure of workflows, jobs, and steps in ASCII format.

        Primarily used for debugging and testing purposes.

        Args:
            data (dict):
                A dictionary containing workflow data organized by repository.

        Returns:
            None

        Raises:
            None
        """
        seen_flows = set()

        for repo, flows in data.items():
            print(f"Repository: {repo}")
            for i, flow in enumerate(flows, start=1):

                # Get the first and last nodes
                first_node = flow[0]
                last_node = flow[-1]

                # Create a hashable identifier for the flow
                flow_identifier = (str(first_node), str(last_node))

                # Check if this flow has already been printed
                if flow_identifier in seen_flows:
                    continue  # Skip duplicate flow

                print(f"  Flow #{i}:")
                for j, node in enumerate(flow, start=1):
                    if "WorkflowNode" in str(node):
                        print(f"    Workflow -> {node}")
                    elif "JobNode" in str(node):
                        print(f"      Job -> {node}")
                    elif "StepNode" in str(node):
                        print(f"        Step -> {node}")
                        if j == len(flow):
                            print(f"       Contents: \n{node.get_step_data()}")
                    elif "ActionNode" in str(node):
                        print(f"        Step -> {node}")
                    else:
                        print(f"    Unknown -> {node}")
