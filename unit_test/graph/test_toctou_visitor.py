import pytest
from unittest.mock import MagicMock, patch
from gatox.workflow_graph.visitors.dispatch_toctou_visitor import DispatchTOCTOUVisitor


@pytest.fixture
def mock_api():
    return MagicMock()


@pytest.fixture
def mock_graph():
    return MagicMock()


def test_no_workflow_dispatch_nodes(mock_graph, mock_api):
    """
    Test when there are no nodes tagged with 'workflow_dispatch'.
    """
    mock_graph.get_nodes_for_tags.return_value = []
    DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    mock_graph.get_nodes_for_tags.assert_called_once_with(["workflow_dispatch"])


def test_dispatch_with_no_paths(mock_graph, mock_api):
    """
    Test when nodes are found but no paths to checkout are discovered.
    """
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]
    mock_graph.dfs_to_tag.return_value = None
    DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    mock_graph.dfs_to_tag.assert_called_once()


def test_dispatch_with_paths_single(mock_graph, mock_api):
    """
    Test with a single path leading to a checkout node.
    """
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]

    # Each path is a list of nodes, here we provide one path
    mock_graph.dfs_to_tag.return_value = [[MagicMock(), MagicMock()]]
    DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    assert mock_graph.dfs_to_tag.call_count == 1


def test_dispatch_multiple_nodes_and_paths(mock_graph, mock_api):
    """
    Test with multiple 'workflow_dispatch' nodes and multiple paths.
    """
    mock_node_1 = MagicMock()
    mock_node_2 = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node_1, mock_node_2]

    path_1 = [MagicMock(), MagicMock()]
    path_2 = [MagicMock(), MagicMock()]
    mock_graph.dfs_to_tag.side_effect = [
        [path_1, path_2],
        None,
    ]
    DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    assert mock_graph.dfs_to_tag.call_count == 2


@patch.object(DispatchTOCTOUVisitor, "_DispatchTOCTOUVisitor__process_path")
def test_exceptions_in_process_path(mock_process, mock_graph, mock_api):
    """
    Test that exceptions in __process_path are caught and handled.
    """
    mock_node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [mock_node]
    mock_graph.dfs_to_tag.return_value = [[MagicMock(), MagicMock()]]
    mock_process.side_effect = Exception("Test error")

    DispatchTOCTOUVisitor.find_dispatch_misconfigurations(mock_graph, mock_api)
    assert mock_process.called
