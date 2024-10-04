from gatox.workflow_graph.graph.tagged_graph import TaggedGraph


def WorkflowRunVistor():
    """ """

    @staticmethod
    def find_artifact_poisoning(graph: TaggedGraph):
        # Unlike pwn requests, we are looking specifically
        # for cases of improper aritfact validation,
        # so we follow different logic focused on that.
        # Now we have all reponodes
        nodes = graph.get_nodes_for_tags(["workflow_run"])

        all_paths = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "checkout", api)
            if paths:
                all_paths.append(paths)
