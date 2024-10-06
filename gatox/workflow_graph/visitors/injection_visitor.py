from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_parser.utility import CONTEXT_REGEX
from gatox.workflow_parser.utility import check_sus, getTokens

from gatox.github.api import Api


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
    def find_injections(graph: TaggedGraph, api: Api):
        """ """

        nodes = graph.get_nodes_for_tags(
            [
                "issue_comment",
                "pull_request_target",
                "workflow_run",
                "fork",
                "issues",
                "discussion",
                "discussion_comment",
            ]
        )

        all_paths = []
        results = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "injectable", api)

            if paths:
                all_paths.append(paths)

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

                        paths = graph.dfs_to_tag(node, "permission_check", api)
                        if paths:
                            approval_gate = True

                        paths = graph.dfs_to_tag(node, "permission_blocker", api)
                        if paths:
                            break

                        env_vars = node.env_vars
                        for key, val in env_vars.items():
                            if type(val) is str:
                                if "github." in val:
                                    env_lookup[key] = val

                        if node.outputs:
                            for o_key, val in node.outputs.items():
                                if "env." in val and val not in env_lookup:
                                    for key in env_lookup.keys():
                                        if key in val:
                                            flexible_lookup[o_key] = env_lookup[key]
                    elif "StepNode" in tags:
                        if "injectable" in tags:
                            # We need to figure out what variables referenced.
                            # also, need to consider the multi tag DFS option
                            # because the true injection might be later.
                            
                            if approval_gate is True:
                                continue

                            filtered_contexts = []

                            for variable in node.contexts:

                                if "inputs." in variable:
                                    if "${{" in variable:
                                        processed_var = CONTEXT_REGEX.findall(variable)
                                        if processed_var:
                                            processed_var = processed_var[0]
                                            if "inputs." in processed_var:
                                                processed_var = processed_var.replace(
                                                    "inputs.", ""
                                                )
                                    else:
                                        processed_var = variable

                                    if processed_var in env_lookup:
                                        original_val = env_lookup[processed_var]
                                        variable = original_val

                                    filtered_contexts.append(variable)

                                elif "env." in variable:
                                    for key, val in env_lookup.items():
                                        if key in variable:
                                            variable = val
                                            filtered_contexts.append(variable)
                                            break
                                else:
                                    filtered_contexts.append(variable)

                            for val in filtered_contexts:
                                if '${{' in val:
                                    val = getTokens(val)
                                    if val:
                                        val = val[0]
                                if val and check_sus(val):
                                    print(val)
                                    results.append(path)
                    elif "WorkflowNode" in tags:
                        if index != 0 and "JobNode" in path[index - 1].get_tags():
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

                # Goal here is to start from the top and keep track
                # of any variables that come out of steps
                # or get passed through workflow calls
                # we also want to make sure to track inside of
                # composite actions.
        for path in results:
            print(path)

        # Now we have all reponodes
