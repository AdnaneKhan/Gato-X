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

from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.caching.cache_manager import CacheManager
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.result_factory import ResultFactory
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.github.api import Api

from gatox.workflow_parser.utility import (
    CONTEXT_REGEX,
    is_within_last_day,
    return_recent,
)
from gatox.notifications.send_webhook import send_slack_webhook


class VisitorUtils:
    """Class to track contextual information during a single visit."""

    @staticmethod
    def _add_results(
        path,
        results: dict,
        issue_type,
        confidence: Confidence = Confidence.UNKNOWN,
        complexity: Complexity = Complexity.ZERO_CLICK,
    ):
        repo_name = path[0].repo_name()
        if repo_name not in results:
            results[repo_name] = []

        if issue_type == IssueType.ACTIONS_INJECTION:
            result = ResultFactory.create_injection_result(path, confidence, complexity)
        elif issue_type == IssueType.PWN_REQUEST:
            result = ResultFactory.create_pwn_result(path, confidence, complexity)
        elif issue_type == IssueType.DISPATCH_TOCTOU:
            result = ResultFactory.create_toctou_result(path, confidence, complexity)
        elif issue_type == IssueType.PR_REVIEW_INJECTON:
            result = ResultFactory.create_review_injection_result(
                path, confidence, complexity
            )
        else:
            raise ValueError(f"Unknown issue type: {issue_type}")

        results[repo_name].append(result)

    @staticmethod
    def initialize_action_node(graph, api, node):
        """
        Initialize an action node by removing the 'uninitialized' tag and setting it up.

        Args:
            graph (TaggedGraph):
                The workflow graph containing all nodes.
            api (Api):
                An instance of the API wrapper to interact with external services.
            node (Node):
                The node to be initialized.

        Returns:
            None

        Raises:
            None
        """
        tags = node.get_tags()
        if "uninitialized" in tags:
            WorkflowGraphBuilder()._initialize_action_node(node, api)
            graph.remove_tags_from_node(node, ["uninitialized"])

    @staticmethod
    def check_mutable_ref(ref, start_tags=set()):
        """
        Check if a reference is mutable based on allowed GitHub SHA patterns.

        Args:
            ref (str):
                The reference string to check.
            start_tags (set, optional):
                A set of starting tags for additional context. Defaults to an empty set.

        Returns:
            bool:
                False if the reference is immutable, True otherwise.
        """
        if "github.event.pull_request.head.sha" in ref:
            return False
        elif "github.event.workflow_run.head.sha" in ref:
            return False
        elif "github.sha" in ref:
            return False
        # If the trigger is pull_request_target and we have a sha in the reference, then this is very likely
        # to be from the original trigger in some form and not a mutable reference, so if it is gated we can suppress.
        elif "sha" in ref and "pull_request_target" in start_tags:
            return False
        # This points to the base branch, so it is not going to be exploitable.
        elif "github.ref" in ref and "||" not in ref:
            return False

        return True

    @staticmethod
    def process_context_var(value):
        """
        Process a context variable by extracting relevant parts.

        Args:
            value (str):
                The context variable string to process.

        Returns:
            str:
                The processed variable.
        """
        processed_var = value
        if "${{" in value:
            processed_var = CONTEXT_REGEX.findall(value)
            if processed_var:
                processed_var = processed_var[0]
                if "inputs." in processed_var:
                    processed_var = processed_var.replace("inputs.", "")
            else:
                processed_var = value
        else:
            processed_var = value
        return processed_var

    @staticmethod
    def append_path(head, tail):
        """
        Append the tail to the head if the tail starts with the last element of the head.

        Args:
            head (list):
                The initial path list.
            tail (list):
                The path to append.

        Returns:
            list:
                The combined path if conditions are met; otherwise, the original head.
        """
        if head and tail and head[-1] == tail[0]:
            head.extend(tail[1:])
        return head

    @staticmethod
    def add_repo_results(data: dict, api: Api):
        """Add results to the repository data."""
        seen = set()
        for _, flows in data.items():
            for flow in flows:
                seen_before = flow.get_first_and_last_hash()
                if not seen_before in seen:
                    seen.add(seen_before)
                else:
                    continue

                repo = CacheManager().get_repository(flow.repo_name())
                repo.set_results(flow)

                if (
                    ConfigurationManager().NOTIFICATIONS["SLACK_WEBHOOKS"]
                    and repo
                    and is_within_last_day(repo.repo_data["pushed_at"])
                ):
                    value = flow.to_machine()
                    commit_date, author, sha = api.get_file_last_updated(
                        flow.repo_name(),
                        ".github/workflows/" + value.get("initial_workflow"),
                    )

                    merge_date = api.get_commit_merge_date(flow.repo_name(), sha)
                    if merge_date:
                        # If there is a PR merged, get the most recent.
                        commit_date = return_recent(commit_date, merge_date)

                    if is_within_last_day(commit_date) and "[bot]" not in author:
                        send_slack_webhook(value)
