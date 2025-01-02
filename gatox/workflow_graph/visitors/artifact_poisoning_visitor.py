from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.github.api import Api


def ArtifactPoisoningVisitor():
    """Visits the graph to find potential artifact poisoning vulnerabilities.

    This is where the workflow runs on workflow_run, then downloads an
    artifact, extracts it, and then runs code from it or uses values from it
    in an unsafe manner.
    """

    @staticmethod
    def find_artifact_poisoning(graph: TaggedGraph, api: Api):
        # Unlike pwn requests, we are looking specifically
        # for cases of improper aritfact validation,
        # so we follow different logic focused on that.
        # Now we have all reponodes
        nodes = graph.get_nodes_for_tags(["workflow_run"])

        all_paths = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "artifact", api)
            if paths:
                all_paths.append(paths)
