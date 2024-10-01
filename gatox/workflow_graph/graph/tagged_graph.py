import networkx as nx


class TaggedGraph(nx.DiGraph):
    def __init__(self, **attr):
        """
        Initialize the TaggedGraph.

        Parameters:
        - **attr: Arbitrary keyword arguments to initialize the graph.
        """
        super().__init__(**attr)
        self.tags = {}  # Dictionary to map tags to sets of nodes

    def dfs_to_tag(self, start_node, target_tag):

        path = list()
        all_paths = list()
        visited = set()

        self._dfs(start_node, target_tag, path, all_paths, visited)

        return all_paths

    def _dfs(self, current_node, target_tag, path, all_paths, visited):
        path.append(current_node)
        visited.add(current_node)

        if target_tag in current_node.get_tags():
            all_paths.append(list(path))
        else:
            for neighbor in self.neighbors(current_node):
                if neighbor not in visited:
                    self._dfs(neighbor, target_tag, path, all_paths, visited)

        path.pop()
        visited.remove(current_node)

    def add_tag(self, tag, nodes=None):
        """
        Add a tag to the graph and associate it with nodes.

        Parameters:
        - tag: The tag to add.
        - nodes: An iterable of nodes to associate with the tag.
        """
        if tag not in self.tags:
            self.tags[tag] = set()
        if nodes:
            self.tags[tag].update(nodes)
            # Ensure that all nodes exist in the graph
            self.add_nodes_from(nodes)

    def remove_tag(self, tag):
        """
        Remove a tag and its associations from the graph.

        Parameters:
        - tag: The tag to remove.
        """
        if tag in self.tags:
            del self.tags[tag]

    def add_node(self, node, **attr):
        """
        Add a node and its tags to the TaggedGraph

        Parameters
        - nod: Node to add
        """
        super().add_node(node, **attr)
        tags = node.get_tags()
        for tag in tags:
            self.add_tag(tag, [node])

    def add_node_with_tags(self, node, tags=None, **attr):
        """
        Add a single node with associated tags.

        Parameters:
        - node: The node to add.
        - tags: An iterable of tags to associate with the node.
        - **attr: Additional attributes for the node.
        """
        super().add_node(node, **attr)
        if tags:
            for tag in tags:
                self.add_tag(tag, [node])

    def add_nodes_with_tags(self, nodes_with_tags, **attr):
        """
        Add multiple nodes with their associated tags.

        Parameters:
        - nodes_with_tags: A dictionary mapping nodes to an iterable of tags.
        - **attr: Additional attributes for the nodes.
        """
        for node, tags in nodes_with_tags.items():
            self.add_node_with_tags(node, tags, **attr)

    def remove_node(self, node):
        """
        Remove a node from the graph and all tag associations.

        Parameters:
        - node: The node to remove.
        """
        super().remove_node(node)
        for tag, nodes in self.tags.items():
            nodes.discard(node)

    def get_nodes_by_tag(self, tag):
        """
        Retrieve all nodes associated with a given tag.

        Parameters:
        - tag: The tag to query.

        Returns:
        - A set of nodes associated with the tag. Returns an empty set if the tag does not exist.
        """
        return self.tags.get(tag, set())

    def get_nodes_for_tags(self, tags: list):
        nodeset = set()

        for tag in tags:
            nodeset.update(self.get_nodes_by_tag(tag))

        return nodeset

    def get_tags_for_node(self, node):
        """
        Retrieve all tags associated with a given node.

        Parameters:
        - node: The node to query.

        Returns:
        - A set of tags associated with the node.
        """
        return {tag for tag, nodes in self.tags.items() if node in nodes}

    def add_tags_to_node(self, node, tags):
        """
        Add one or more tags to an existing node.

        Parameters:
        - node: The node to tag.
        - tags: An iterable of tags to associate with the node.
        """
        if node not in self:
            raise nx.NetworkXError(f"Node {node} is not in the graph.")
        for tag in tags:
            self.add_tag(tag, [node])

    def remove_tags_from_node(self, node, tags):
        """
        Remove one or more tags from a node.

        Parameters:
        - node: The node from which to remove tags.
        - tags: An iterable of tags to dissociate from the node.
        """
        for tag in tags:
            if tag in self.tags:
                self.tags[tag].discard(node)
                # Optionally remove the tag if no nodes are associated
                if not self.tags[tag]:
                    del self.tags[tag]
