from gatox.workflow_graph.graph.tagged_graph import TaggedGraph


def WorkflowRunVistor():
    """ """

    @staticmethod
    def find_artifact_poisoning(graph: TaggedGraph):
        # Unlike pwn requests, we are looking specifically
        # for cases of improper aritfact validation,
        # so we follow different logic focused on that.
        pass
