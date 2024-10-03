from gatox.workflow_graph.graph.tagged_graph import TaggedGraph


class PwnRequestVisitor:
    """ """

    @staticmethod
    def check_gating():
        pass
    

    @staticmethod
    def find_pwn_requests(graph: TaggedGraph):

        # Now we have all reponodes
        nodes = graph.get_nodes_for_tags(
            ["issue_comment", "pull_request_target", "workflow_run"]
        )

        all_paths = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "checkout")
            if paths:
                all_paths.append(paths)

        results = []

        for path_set in all_paths:
            for path in path_set:

                input_lookup = {}

                for index, node in enumerate(path):
                    if "JobNode" in node.get_tags():
                        if node.deployments:
                            print(node.deployments)
                        
                    elif "StepNode" in node.get_tags():

                        

                        if node.get_attrs()['is_hard_gate']:
                            print("HARD GATE - CONT")
                        
                        if node.get_attrs()['is_soft_gate']:
                            print("SOFT GATE")
                    elif "WorkflowNode" in node.get_tags():

                        if index != 0 and 'JobNode' in path[index - 1].get_tags():
                            # Caller node
                            node_params = path[index - 1].params
                            # Set lookup for input params
                            input_lookup[node] = node_params

                        pass

                # Start at the workflow, and iterate down

                # If workflow has env vars, then capture them.

                # For every job/step we determine if there is a gate

                # There are two types of gates:

                # Hard gates, which mean that no matter what the workflow cannot
                # proceed from a forked context.

                # Soft gates, means the maintainer needs to approve in some form.

                # Once we hit the checkout, then things get interesting.

                # We have to analyze the reference to determine if it is mutable or not.
                # If it comes from an input, then we need to check if it is injectable.

                # If soft gate and mutable, then we have TOCTOU
                # If soft gate and immutable, then we suppress.

                # We then continue until we find a sink in the same job.

                # If we find a sink, no gate, then we have HIGH
                # If no sink but we have untrusted checkout without gate, then MEDIUM
                # If we have TOCTOU and no sink then LOW.
