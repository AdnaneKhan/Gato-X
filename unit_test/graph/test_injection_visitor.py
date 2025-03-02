import pytest
from unittest.mock import Mock, patch
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.workflow_graph.visitors.injection_visitor import InjectionVisitor
from gatox.github.api import Api
from gatox.workflow_graph.nodes.workflow import WorkflowNode
from gatox.workflow_graph.nodes.job import JobNode
from gatox.workflow_graph.nodes.step import StepNode
from gatox.workflow_graph.nodes.action import ActionNode


@pytest.fixture
def mock_api():
    mock_api = Mock(spec=Api)
    mock_api.get_all_environment_protection_rules.return_value = {}
    return mock_api


@pytest.fixture
def mock_graph():
    return Mock(spec=TaggedGraph)


def test_find_injections_no_nodes(mock_graph, mock_api, capsys):
    """Test when no nodes are found with injection tags"""
    mock_graph.get_nodes_for_tags.return_value = []

    results = InjectionVisitor.find_injections(mock_graph, mock_api)
    assert results == {}
    # captured = capsys.readouterr()
    # assert "INJECT:" in captured.out
    # mock_graph.get_nodes_for_tags.assert_called_once()


# def test_find_injections_with_workflow_run(mock_graph, mock_api):
#     """Test that workflow_run tag is included when ignore_workflow_run is False"""
#     InjectionVisitor.find_injections(mock_graph, mock_api, ignore_workflow_run=False)

#     call_args = mock_graph.get_nodes_for_tags.call_args[0][0]
#     assert "workflow_run" in call_args


# def test_find_injections_ignore_workflow_run(mock_graph, mock_api):
#     """Test that workflow_run tag is excluded when ignore_workflow_run is True"""
#     InjectionVisitor.find_injections(mock_graph, mock_api, ignore_workflow_run=True)

#     call_args = mock_graph.get_nodes_for_tags.call_args[0][0]
#     assert "workflow_run" not in call_args


# def test_find_injections_with_path(mock_graph, mock_api, capsys):
#     """Test path analysis with various node types"""
#     workflow_node = Mock(spec=WorkflowNode)
#     workflow_node.get_tags.return_value = ["WorkflowNode"]
#     workflow_node.get_env_vars.return_value = {"TEST_ENV": "github.event.test"}

#     job_node = Mock(spec=JobNode)
#     job_node.get_tags.return_value = ["JobNode"]
#     job_node.get_env_vars.return_value = {}
#     job_node.deployments = []

#     step_node = Mock(spec=StepNode)
#     step_node.get_tags.return_value = ["StepNode", "injectable"]
#     step_node.contexts = ["github.event.test"]

#     path = [workflow_node, job_node, step_node]

#     mock_graph.get_nodes_for_tags.return_value = [workflow_node]
#     mock_graph.dfs_to_tag.return_value = [path]

#     InjectionVisitor.find_injections(mock_graph, mock_api)

#     captured = capsys.readouterr()
#     assert "INJECT:" in captured.out


# def test_find_injections_with_approval_gate(mock_graph, mock_api):
#     """Test path analysis with approval gate"""
#     job_node = Mock(spec=JobNode)
#     job_node.get_tags.return_value = ["JobNode"]
#     job_node.__repo_name = "test/repo"
#     job_node.deployments = ["prod"]
#     job_node.get_env_vars.return_value = {}

#     step_node = Mock(spec=StepNode)
#     step_node.get_tags.return_value = ["StepNode", "injectable"]
#     step_node.contexts = []

#     path = [job_node, step_node]

#     mock_graph.get_nodes_for_tags.return_value = [job_node]
#     mock_graph.dfs_to_tag.return_value = [path]
#     mock_api.get_all_environment_protection_rules.return_value = {"prod": True}

#     InjectionVisitor.find_injections(mock_graph, mock_api)

#     mock_api.get_all_environment_protection_rules.assert_called_with("test/repo")


def test_find_injections_with_action_node(mock_graph, mock_api):
    """Test path analysis with action node"""
    action_node = Mock(spec=ActionNode)
    action_node.get_tags.return_value = ["ActionNode"]

    mock_graph.get_nodes_for_tags.return_value = [action_node]
    mock_graph.dfs_to_tag.return_value = [[action_node]]

    InjectionVisitor.find_injections(mock_graph, mock_api)

    mock_graph.get_nodes_for_tags.assert_called_once()
