from gatox.workflow_graph.graph.tagged_graph import TaggedGraph

class InjectionVisitor:
    """This class implements a graph visitor tasked with identifying
    injection issues from workflows.
    """

    @staticmethod
    def check_gating():
        # For injection, gating is more firm because
        # injection issues are very unlikely to be exploited.
        pass

    @staticmethod
    def find_injections(graph):
        """
        """

        nodes = graph.get_nodes_for_tags([
            "issue_comment",
            "pull_request_target",
            "workflow_run",
            "fork",
            "issues",
            "discussion",
            "discussion_comment"
        ])

        all_paths = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "injection")
            if paths:
                all_paths.append(paths)

        for path_set in all_paths:
            for path in path_set:
                print(path)

                # Goal here is to start from the top and keep track
                # of any variables that come out of steps
                # or get passed through workflow calls
                # we also want to make sure to track inside of
                # composite actions.
                

        # Now we have all reponodes
        

