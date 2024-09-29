from networkx import nx

from gatox.workflow_graph.nodes.step import StepNode
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder

class GraphVisitor():
    """This class aims to traverse Gato-X workflow/job/step graph with the aim
    of finding paths from workflows that run on risky checkouts to steps that
    contain sinks for injection or code execution.

    Unlike the mess that was the previous workflow parser, I am trying to
    follow a proper traversal algorithm. Each path represents an injection
    or Pwn request vulnerability that Gato-X will report.
    """

    def is_target_leaf_node(node):
        """Returns true if the node here is a target terminal node.
        """
        # For now, using this check. Need to move towards getting a minimal example
        # working.

        return (
            node.get_attrs().get('injectable') or
            node.get_attrs().get('is_checkout')
        )

    def can_traverse_gate(node_attributes, path_context):

        hard_gate = node_attributes.get('is_hard_gate')
        soft_gate = node_attributes.get('is_soft_gate')

        if soft_gate:
            # Allow traversal if conditions are met
            if path_context.get('has_mutable_checkout', False) and path_context.get('trigger') == 'pull_request_target:labeled':
                return True
            else:
                return False
        elif hard_gate == 'permission_gate':
            # Define additional gate logic as needed
            return False
        else:
            # Non-gated or unrecognized gate types allow traversal
            return True
    
    @classmethod
    def forward_traversal_generator(cls, graph, workflow_nodes):
        visited = set()
        for workflow_node in workflow_nodes:
            initial_context = {'trigger': 'pull_request_target:labeled', 'context_is_mutable': False}
            yield from cls.traverse_node(cls, graph, workflow_node, [workflow_node], initial_context, visited)

    @classmethod
    def traverse_node(cls, graph, node, path_so_far, context, visited):
        visited_key = (node, frozenset(context.items()))
        if visited_key in visited:
            return
        visited.add(visited_key)

        node_attributes = node.get_attrs()

        # Update context
        #f node_attributes.get('modifies_context'):
        #    context['context_is_mutable'] = True

        # Hard gates are ones that we cannot bypass
        # from a fork, such as a check that the PR is not from a fork.

        # Update contexts in case there are any job outputs that
        # we need to pass down.
        #if 'JobNode' in node.get_attrs() or 'StepNode' in node.get_attrs():
        #   cls.update_context(node, context)
 
        if not cls.can_traverse_gate(node_attributes, context):
            return

        # Check if node meets target criteria
        if cls.is_target_leaf_node(node_attributes):
            yield {'path': list(path_so_far), 'context': context.copy()}

        # Traverse successors
        for succ in graph.successors(node):
            if succ not in path_so_far:
                new_path = path_so_far + [succ]
                yield from cls.traverse_node(graph, succ, new_path, context.copy(), visited)

    # # Usage
    # for result in forward_traversal_generator(G, workflow_nodes):
    #     path_nodes = result['path']
    #     path_context = result['context']
    #     print(f"Found path: {path_nodes} with context: {path_context}")
