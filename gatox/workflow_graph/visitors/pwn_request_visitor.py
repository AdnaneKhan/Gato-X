from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.github.api import Api
from gatox.workflow_parser.utility import CONTEXT_REGEX
from gatox.caching.cache_manager import CacheManager


class PwnRequestVisitor:
    """Visits the graph to find potential Pwn Requests."""

    @staticmethod
    def _finalize_result():
        """Takes a known reachable checkout and attempts to find an associated sink."""

    @staticmethod
    def find_pwn_requests(graph: TaggedGraph, api: Api):
        """ """

        # Now we have all reponodes
        nodes = graph.get_nodes_for_tags(
            [
                "issue_comment",
                "pull_request_target",
                "workflow_run",
                "pull_request_target:labeled",
            ]
        )

        all_paths = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "checkout", api)
            if paths:
                all_paths.append(paths)

        results = {}
        rule_cache = {}

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
                            if node.repo_name in rule_cache:
                                rules = rule_cache[node.repo_name]
                            else:

                                rules = api.get_all_environment_protection_rules(
                                    node.repo_name
                                )
                                rule_cache[node.repo_name] = rules
                            for deployment in node.deployments:
                                if deployment in rules:
                                    approval_gate = True
                                    continue

                        paths = graph.dfs_to_tag(node, "permission_blocker", api)
                        if paths:
                            break

                        paths = graph.dfs_to_tag(node, "permission_check", api)
                        if paths:
                            approval_gate = True

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
                            if "inputs." in node.metadata:
                                if "${{" in node.metadata:
                                    processed_var = CONTEXT_REGEX.findall(node.metadata)
                                    if processed_var:
                                        processed_var = processed_var[0]
                                        if "inputs." in processed_var:
                                            processed_var = processed_var.replace(
                                                "inputs.", ""
                                            )
                                    else:
                                        processed_var = node.metadata
                                else:
                                    processed_var = node.metadata

                                if processed_var in env_lookup:
                                    original_val = env_lookup[processed_var]
                                    checkout_ref = original_val
                                elif processed_var in input_lookup:
                                    checkout_ref = input_lookup[processed_var]

                            elif "env." in node.metadata:
                                for key, val in env_lookup.items():
                                    if key in node.metadata:
                                        checkout_ref = val
                                        break

                            if (
                                approval_gate
                                and VisitorUtils.check_mutable_ref(checkout_ref)
                            ) or not approval_gate:
                                VisitorUtils._add_results(path, results)
                                sinks = graph.dfs_to_tag(node, "sink", api)
                                if sinks:
                                    print("We found sinks!")

                        if node.outputs:
                            for key, val in node.outputs.items():
                                if "env." in val:
                                    pass

                        if node.hard_gate:
                            break

                        if node.soft_gate:
                            approval_gate = True

                    elif "WorkflowNode" in tags:
                        if index != 0 and "JobNode" in path[index - 1].get_tags():
                            # Caller job node
                            node_params = path[index - 1].params
                            # Set lookup for input params
                            input_lookup.update(node_params)
                        if index == 0:
                            repo = CacheManager().get_repository(node.repo_name)
                            if repo.is_fork():
                                break

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
                        VisitorUtils.initialize_action_node(graph, api, node)

        print("PWN:")
        VisitorUtils.ascii_render(results)
