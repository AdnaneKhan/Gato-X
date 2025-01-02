from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder


class VisitorUtils:
    """Class to track contextual information during a a single visit."""

    @staticmethod
    def _add_results(path, results: dict):
        """ """
        repo_name = path[0].repo_name
        if repo_name not in results:
            results[repo_name] = []

        results[repo_name].append(path)

    @staticmethod
    def initialize_action_node(graph, api, node):
        tags = node.get_tags()
        if "uninitialized" in tags:
            WorkflowGraphBuilder()._initialize_action_node(node, api)
            graph.remove_tags_from_node(node, ["uninitialized"])

    @staticmethod
    def check_mutable_ref(ref):

        if "github.event.pull_request.head.sha" in ref:
            return False
        elif "github.event.workflow_run.head.sha" in ref:
            return False
        elif "github.sha" in ref:
            return False
        # This points to the base branch, so it is not going to be
        # exploitable.
        elif "github.ref" in ref and "||" not in ref:
            return False

        return True

    @staticmethod
    def append_path(head, tail):
        """Appends the tail to the head ONLY if the tail
        starts with the last element of the head. This is
        to faciliate merging paths to a sink into a result path.
        """
        if head and tail and head[-1] == tail[0]:
            head.extend(tail[1:])
        return head

    @staticmethod
    def ascii_render(data: dict):
        """
        Render the nested structure of workflows -> jobs -> steps in ASCII format.

        Primarily for debugging / testing.
        """
        for repo, flows in data.items():
            print(f"Repository: {repo}")
            for i, flow in enumerate(flows, start=1):
                print(f"  Flow #{i}:")
                for node in flow:
                    if "WorkflowNode" in str(node):
                        print(f"    Workflow -> {node}")
                    elif "JobNode" in str(node):
                        print(f"      Job -> {node}")
                    elif "StepNode" in str(node):
                        print(f"        Step -> {node}")
                    elif "ActionNode" in str(node):
                        print(f"        Step -> {node}")
                    else:
                        print(f"    Unknown -> {node}")
