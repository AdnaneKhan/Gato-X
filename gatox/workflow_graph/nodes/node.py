"""
Copyright 2025, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


class Node:
    """
    A base class representing a generic node with a name.

    Attributes:
        name (str): The name of the node.
    """

    def __init__(self, name):
        """
        Initialize a Node instance.

        Args:
            name (str): The name of the node.
        """
        self.name = name

    def __repr__(self):
        """
        Return a string representation of the Node instance.

        Returns:
            str: A string representation of the Node instance.
        """
        return f"{self.__class__.__name__}('{self.name}')"

    def __hash__(self):
        """
        Return the hash value of the Node instance.

        Returns:
            int: The hash value of the Node instance.
        """
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        """
        Check if two Node instances are equal.

        Args:
            other (Node): Another Node instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def get_if(self):
        return ""

    def get_needs(self):
        """
        Get the needs associated with the Node instance.

        Returns:
            list: An empty list.
        """
        return []

    def get_repr(self):
        """
        Get the representation of the Node instance.

        Returns:
            value: A dict representation of the Node instance.
        """
        value = {
            "node": str(self),
        }
        return value

    def get_tags(self):
        """
        Get the tags associated with the Node instance.

        Returns:
            set: A set containing the class name of the Node instance.
        """
        tags = set([self.__class__.__name__])
        return tags
