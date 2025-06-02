import pytest
from unittest.mock import MagicMock, patch
from gatox.workflow_graph.visitors.pwn_request_visitor import PwnRequestVisitor
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.github.api import Api
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.issue_type import IssueType


@pytest.fixture
def mock_graph():
    return MagicMock(spec=TaggedGraph)


@pytest.fixture
def mock_api():
    return MagicMock(spec=Api)


@pytest.fixture
def mock_cache_manager():
    with patch(
        "gatox.workflow_graph.visitors.pwn_request_visitor.CacheManager"
    ) as MockCache:
        instance = MockCache.return_value
        instance.get_repository.return_value = MagicMock(is_fork=lambda: False)
        yield instance


async def test_find_pwn_requests_no_nodes(mock_graph, mock_api, mock_cache_manager):
    mock_graph.get_nodes_for_tags.return_value = []
    with patch.object(VisitorUtils, "add_repo_results"):
        await PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)


async def test_find_pwn_requests_with_nodes(mock_graph, mock_api, mock_cache_manager):
    node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [node]
    mock_graph.dfs_to_tag.return_value = [[node]]

    with (
        patch.object(PwnRequestVisitor, "_process_single_path") as mock_process,
        patch.object(VisitorUtils, "add_repo_results"),
    ):
        await PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)
        mock_process.assert_called_once()


async def test_process_single_path_with_memoization_logic(
    mock_graph, mock_api, mock_cache_manager
):
    """
    Test that permission blockers and approval gates are memoized correctly,
    and results are only suppressed when blocker nodes are actually in the final path.
    """
    # Create mock nodes for the path
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    # Create mock blocker and approval gate nodes (not in main path)
    blocker_node = MagicMock()
    blocker_node.get_tags.return_value = ["permission_blocker"]

    approval_gate_node = MagicMock()
    approval_gate_node.get_tags.return_value = ["permission_check"]

    # Create sink node
    sink_node = MagicMock()
    sink_node.get_tags.return_value = ["sink"]

    # Set up the path
    path = [workflow_node, job_node, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            # Return paths to blocker nodes that are NOT in the main path
            return [[blocker_node]]
        elif tag == "permission_check":
            # Return paths to approval gate nodes that are NOT in the main path
            return [[approval_gate_node]]
        elif tag == "sink":
            # Return sink path
            return [[sink_node]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock API calls
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    # Mock VisitorUtils methods
    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Verify that results were added (since blocker nodes are not in the main path)
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args

        # Check that the path was passed correctly
        assert call_args[0][0] == path
        assert call_args[0][1] == results
        assert call_args[0][2] == IssueType.PWN_REQUEST

        # Verify complexity and confidence
        assert (
            call_args[1]["complexity"] == Complexity.ZERO_CLICK
        )  # No approval gate in path
        assert call_args[1]["confidence"] == Confidence.HIGH  # Sink found


async def test_process_single_path_blocker_in_path_suppresses_results(
    mock_graph, mock_api, mock_cache_manager
):
    """
    Test that results are suppressed when a blocker node is actually in the final path.
    """
    # Create mock nodes
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    # This blocker node is part of the main path
    blocker_step = MagicMock()
    blocker_step.get_tags.return_value = ["StepNode", "permission_blocker"]
    blocker_step.is_checkout = False
    blocker_step.outputs = None
    blocker_step.hard_gate = False
    blocker_step.soft_gate = False

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    sink_node = MagicMock()
    sink_node.get_tags.return_value = ["sink"]

    # Path includes the blocker node
    path = [workflow_node, job_node, blocker_step, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            # Return path that includes the blocker_step (which is in main path)
            return [[blocker_step]]
        elif tag == "permission_check":
            return []
        elif tag == "sink":
            return [[sink_node]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock API calls
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    # Mock VisitorUtils methods
    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Verify that results were NOT added (blocker node is in the path)
        mock_add_results.assert_not_called()


async def test_process_single_path_approval_gate_affects_complexity(
    mock_graph, mock_api, mock_cache_manager
):
    """
    Test that approval gate nodes in the path correctly affect complexity calculation.
    """
    # Create mock nodes
    workflow_node = MagicMock()
    workflow_node.get_tags.return_value = ["WorkflowNode", "pull_request_target"]
    workflow_node.excluded.return_value = False
    workflow_node.get_env_vars.return_value = {}
    workflow_node.repo_name.return_value = "test/repo"

    job_node = MagicMock()
    job_node.get_tags.return_value = ["JobNode"]
    job_node.deployments = None
    job_node.outputs = None
    job_node.repo_name.return_value = "test/repo"

    # This approval gate node is part of the main path
    approval_step = MagicMock()
    approval_step.get_tags.return_value = ["StepNode", "permission_check"]
    approval_step.is_checkout = False
    approval_step.outputs = None
    approval_step.hard_gate = False
    approval_step.soft_gate = False

    checkout_step = MagicMock()
    checkout_step.get_tags.return_value = ["StepNode"]
    checkout_step.is_checkout = True
    checkout_step.metadata = "refs/heads/main"
    checkout_step.outputs = None
    checkout_step.hard_gate = False
    checkout_step.soft_gate = False

    sink_node = MagicMock()
    sink_node.get_tags.return_value = ["sink"]

    # Path includes the approval gate node
    path = [workflow_node, job_node, approval_step, checkout_step]

    # Mock the graph DFS calls
    def mock_dfs_side_effect(node, tag, api):
        if tag == "permission_blocker":
            return []
        elif tag == "permission_check":
            # Return path that includes the approval_step (which is in main path)
            return [[approval_step]]
        elif tag == "sink":
            return [[sink_node]]
        return []

    mock_graph.dfs_to_tag.side_effect = mock_dfs_side_effect

    # Mock API calls
    mock_api.get_all_environment_protection_rules.return_value = {}

    results = {}
    rule_cache = {}

    # Mock VisitorUtils methods
    with (
        patch.object(VisitorUtils, "process_context_var", return_value="processed"),
        patch.object(VisitorUtils, "check_mutable_ref", return_value=True),
        patch.object(VisitorUtils, "append_path"),
        patch.object(VisitorUtils, "_add_results") as mock_add_results,
    ):

        await PwnRequestVisitor._process_single_path(
            path, mock_graph, mock_api, rule_cache, results
        )

        # Verify that results were added
        mock_add_results.assert_called_once()
        call_args = mock_add_results.call_args

        # Check that complexity is TOCTOU due to effective approval gate
        assert call_args[1]["complexity"] == Complexity.TOCTOU
        assert call_args[1]["confidence"] == Confidence.HIGH
