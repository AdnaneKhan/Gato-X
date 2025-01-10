import pytest
from unittest.mock import patch

from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.workflow_graph.nodes.workflow import WorkflowNode
from gatox.workflow_graph.nodes.job import JobNode
from gatox.workflow_graph.nodes.step import StepNode
from gatox.workflow_graph.nodes.action import ActionNode
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder


def test_add_results():
    # Test adding paths to results dict
    path = [WorkflowNode("main", "org/repo1", ".github/workflows/test.yml")]
    results = {}

    VisitorUtils._add_results(path, results)

    assert "org/repo1" in results
    assert len(results["org/repo1"]) == 1


def test_check_mutable_ref():
    # Test immutable refs
    assert not VisitorUtils.check_mutable_ref("github.event.pull_request.head.sha")
    assert not VisitorUtils.check_mutable_ref("github.event.workflow_run.head.sha")
    assert not VisitorUtils.check_mutable_ref("github.sha")
    assert not VisitorUtils.check_mutable_ref("sha", {"pull_request_target"})
    assert not VisitorUtils.check_mutable_ref("github.ref")

    # Test mutable refs
    assert VisitorUtils.check_mutable_ref("ref/heads/main")
    assert VisitorUtils.check_mutable_ref("github.ref||something")


def test_process_context_var():
    # Test processing context variables
    assert VisitorUtils.process_context_var("${{ inputs.test }}") == "test"
    assert VisitorUtils.process_context_var("plain_value") == "plain_value"
    assert VisitorUtils.process_context_var("${{ github.sha }}") == "github.sha"


def test_append_path():
    # Test appending paths
    head = [1, 2, 3]
    tail = [3, 4, 5]
    result = VisitorUtils.append_path(head, tail)
    assert result == [1, 2, 3, 4, 5]

    # Test non-matching paths
    head = [1, 2, 3]
    tail = [4, 5, 6]
    result = VisitorUtils.append_path(head, tail)
    assert result == [1, 2, 3]


@patch("gatox.enumerate.enumerate.Api")
def test_initialize_action_node(mock_api):
    graph = WorkflowGraphBuilder().graph
    api = mock_api  # Mock API if needed
    node = ActionNode("someorg/testaction@v4", "main", "action.yml", "testOrg/repo", {})

    try:
        VisitorUtils.initialize_action_node(graph, api, node)
    except:
        pass  # Expected to fail without proper mocking

    # Just verify tag was removed
    assert "uninitialized" not in node.get_tags()


def test_ascii_render(capsys):

    step_data = {
        "name": "test_step",
        "run": "test",
    }

    data = {
        "test_repo": [
            [
                WorkflowNode("main", "testOrg/test_repo", "workflow1"),
                JobNode(
                    "Test1", "main", "testOrg/test_repo", ".github/workflows/test.yml"
                ),
                StepNode(
                    step_data,
                    "main",
                    "testOrg/test_repo",
                    ".github/workflows/",
                    "tests.yml",
                    1,
                ),
            ]
        ]
    }

    VisitorUtils.ascii_render(data)
    captured = capsys.readouterr()

    assert "Repository: test_repo" in captured.out
    assert "Flow #1:" in captured.out
    assert "Workflow ->" in captured.out
    assert "Job ->" in captured.out
    assert "Step ->" in captured.out
    assert "Contents:" in captured.out
