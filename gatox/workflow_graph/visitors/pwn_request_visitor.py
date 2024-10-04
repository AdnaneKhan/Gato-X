from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.github.api import Api
from gatox.workflow_parser.utility import CONTEXT_REGEX

class PwnRequestVisitor:
    """
    """

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
        elif "github.ref" in ref and '||' not in ref:
            return False
        
        return True

    @staticmethod
    def _finalize_result():
        """Takes a known reachable checkout and attempts to find an associated sink.
        """
    
    @staticmethod
    def find_pwn_requests(graph: TaggedGraph, api: Api):

        # Now we have all reponodes
        nodes = graph.get_nodes_for_tags(
            ["issue_comment", "pull_request_target", "workflow_run", "pull_request_target:labeled"]
        )

        all_paths = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "checkout", api)
            if paths:
                all_paths.append(paths)

        results = []

        for path_set in all_paths:
            for path in path_set:
                input_lookup = {}
                env_lookup = {}
                flexible_lookup = {}

                approval_gate = False

                for index, node in enumerate(path):
                    tags = node.get_tags()

                    if "JobNode" in tags:
                        # Check deployment environment rules
                        if node.deployments:
                            rules = api.get_all_environment_protection_rules(
                                    node.repo_name
                            )
                            for deployment in node.deployments:
                                if deployment in rules:
                                    approval_gate = True
                                    continue

                        paths = graph.dfs_to_tag(node, "permission_check", api)
                        if paths:
                            approval_gate = True

                        paths = graph.dfs_to_tag(node, "permission_blocker", api)
                        if paths:
                            break

                        if node.outputs:
                            for o_key, val in node.outputs.items():
                                if "env." in val and val not in env_lookup:
                                    for key in env_lookup.keys():
                                        if key in val:
                                            flexible_lookup[o_key] = env_lookup[key]
                    elif "StepNode" in tags:
                        
                        if node.is_checkout:
                            # Terminal
                            checkout_ref = node.metadata
                            if 'inputs.' in node.metadata:
                                if '${{' in node.metadata:
                                    processed_var = CONTEXT_REGEX.findall(node.metadata)
                                    if processed_var:
                                        processed_var = processed_var[0]
                                        if 'inputs.' in processed_var:
                                            processed_var = processed_var.replace('inputs.', '')
                                else:
                                    processed_var = node.metadata

                                if processed_var in env_lookup:
                                    original_val = env_lookup[processed_var]
                                    checkout_ref = original_val

                            elif "env." in node.metadata:
                                for key, val in env_lookup.items():
                                    if key in node.metadata:
                                        checkout_ref = val
                                        break
                                 
                            if approval_gate and PwnRequestVisitor.check_mutable_ref(checkout_ref):
                                results.append(path)
                                break
                            elif not approval_gate:
                                results.append(path)
                                break

                        if node.outputs:
                            for key, val in node.outputs.items():
                                if "env." in val:
                                    pass
                                
                    elif "WorkflowNode" in tags:
                        if index != 0 and 'JobNode' in path[index - 1].get_tags():
                            # Caller job node
                            node_params = path[index - 1].params
                            # Set lookup for input params
                            input_lookup.update(node_params)
                        if index == 0:
                            if "pull_request_target:labeled" in tags:
                                approval_gate = True

                            # Check workflow environment variables.
                            # for env vars that are github.event.*
                            env_vars = node.env_vars
                            for key, val in env_vars.items():
                                if type(val) is str:
                                    if "github." in val:
                                        env_lookup[key] = val
                                
                    elif "ActionNode" in tags:
                        tags = node.get_tags()
                
                        if 'uninitialized' in tags: 
                            WorkflowGraphBuilder()._initialize_action_node(node, api)
                            graph.remove_tags_from_node(node, ['uninitialized'])
        print(results)

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
