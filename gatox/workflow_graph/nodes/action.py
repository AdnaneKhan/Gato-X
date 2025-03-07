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

from gatox.workflow_graph.nodes.node import Node

from gatox.workflow_parser.utility import decompose_action_ref, starts_with_any


class ActionNode(Node):
    """
    Wrapper class for a GitHub Actions workflow action.

    Attributes:
        name (str): A unique identifier for the action node.
        params (dict): Parameters associated with the action node.
        is_sink (bool): Indicates if the action is a sink.
        is_checkout (bool): Indicates if the action is a checkout.
        if_condition (str): The condition under which the action runs.
        is_gate (bool): Indicates if the action is a gate.
        metadata (bool): Metadata associated with the action.
        initialized (bool): Indicates if the action is initialized.
        type (str): The type of the action.
    """

    # Set of actions that we do not need
    # to pull down yamls for.
    KNOWN_GOOD = set(
        [
            "azure/login",
            "github/codeql-action/analyze",
            "docker/login-action",
            "github/codeql-action",
            "github/codeql-action/init",
            "codecov/codecov-action",
            "docker/setup-buildx-action",
            "actions-cool/check-user-permission",
        ]
    )

    KNOWN_SINKS = set(
        [
            "sonarsource/sonarcloud-github-action",
            "actions/jekyll-build-pages",
            "bridgecrewio/checkov-action",
            "pre-commit/action",
            "oxsecurity/megalinter",
            "andresz1/size-limit-action",
        ]
    )

    ARTIFACT_RETRIEVERS = set(
        [
            "actions/download-artifact",
        ]
    )

    KNOWN_GATES = set(
        [
            "sushichop/action-repository-permission",
            "actions-cool/check-user-permission",
            "shopify/snapit",
            "peter-evans/slash-command-dispatch",
            "TheModdingInquisition/actions-team-membership",
            "prince-chrismc/check-actor-permissions-action",
            "lannonbr/repo-permission-check-action",
            "skjnldsv/check-actor-permission",
        ]
    )

    GOOD_PREFIXES = set(
        [
            "actions/",
            "docker/",
            "octokit/",
            "github/",
        ]
    )

    KNOWN_HARD_GATES = set(["dependabot/fetch-metadata"])

    def __init__(
        self, action_name: str, ref: str, action_path: str, repo_name: str, params: dict
    ):
        """
        Constructor for the action wrapper.

        Args:
            action_name (str): The name of the action.
            ref (str): The reference (e.g., branch or tag).
            action_path (str): The path to the action file.
            repo_name (str): The name of the repository.
            params (dict): Parameters associated with the action.
        """
        # Create a unique ID for this action.
        self.name = f"{repo_name}:{ref}:{action_path}:{action_name}"
        self.is_sink = False
        self.is_checkout = False
        self.if_condition = ""
        self.is_gate = False
        self.hard_gate = False
        self.metadata = False
        self.initialized = False
        self.caller_ref = ref
        self.type = "UNK"

        self.action_info = decompose_action_ref(action_name, repo_name)

        if not self.action_info["local"]:
            if "@" in self.action_info["key"]:
                initial_path = self.action_info["key"].split("@")[0]
            else:
                initial_path = self.action_info["key"]
            # We only check actions if they belong to another
            # repo in the same org. This is because most 3P actions
            # will use node. We are interested in organizations that
            # use a centralized repo with reusable composite actions to prevent
            # duplication.
            if not self.action_info["key"].startswith(repo_name.split("/")[0]):
                self.initialized = True
            # We don't need to download official GitHub Actions.
            if starts_with_any(self.action_info["key"], self.GOOD_PREFIXES):
                self.initialized = True
            if initial_path in self.KNOWN_GOOD:
                self.initialized = True
            if initial_path in self.KNOWN_GATES:
                self.is_gate = True
            if initial_path in self.KNOWN_HARD_GATES:
                self.is_gate = True
                self.hard_gate = True
            if initial_path in self.KNOWN_SINKS:
                self.is_sink = True
        elif self.action_info["docker"]:
            # We don't resolve docker actions
            self.initialized = True

    def __hash__(self):
        """
        Return the hash value of the ActionNode instance.

        Returns:
            int: The hash value of the ActionNode instance.
        """
        return hash((self.name, self.__class__.__name__))

    def __eq__(self, other):
        """
        Check if two ActionNode instances are equal.

        Args:
            other (ActionNode): Another ActionNode instance to compare with.

        Returns:
            bool: True if the instances are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and self.name == other.name

    def get_step_data(self):
        """ """
        return self.action_info["key"]

    def get_tags(self):
        """
        Get the tags associated with the ActionNode instance.

        Returns:
            set: A set containing the class name of the ActionNode instance.
        """
        tags = set([self.__class__.__name__])

        if self.is_checkout:
            tags.add("checkout")

        if self.is_sink:
            tags.add("sink")

        if not self.initialized:
            tags.add("uninitialized")

        if self.is_gate:
            tags.add("permission_check")

        return tags

    def get_attrs(self):
        """
        Get the attributes associated with the ActionNode instance.

        Returns:
            dict: A dictionary containing attributes of the ActionNode instance.
        """
        return {
            self.__class__.__name__: True,
            "type": self.type,
            "is_soft_gate": False,
            "is_hard_gate": False,
        }
