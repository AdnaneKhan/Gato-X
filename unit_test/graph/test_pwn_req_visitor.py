import pytest
from unittest import mock
from unittest.mock import MagicMock, patch
from gatox.workflow_graph.visitors.pwn_request_visitor import PwnRequestVisitor
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.github.api import Api
from gatox.workflow_graph.visitors.visitor_utils import VisitorUtils
from gatox.caching.cache_manager import CacheManager


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


def test_find_pwn_requests_no_nodes(mock_graph, mock_api, mock_cache_manager):
    mock_graph.get_nodes_for_tags.return_value = []
    with patch.object(VisitorUtils, "ascii_render") as mock_render:
        PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)
        mock_render.assert_called_with({})


def test_finalize_result_not_implemented():
    with pytest.raises(NotImplementedError):
        PwnRequestVisitor._finalize_result()


def test_find_pwn_requests_with_nodes(mock_graph, mock_api, mock_cache_manager):
    node = MagicMock()
    mock_graph.get_nodes_for_tags.return_value = [node]
    mock_graph.dfs_to_tag.return_value = [[node]]

    with (
        patch.object(PwnRequestVisitor, "_process_single_path") as mock_process,
        patch.object(VisitorUtils, "ascii_render") as mock_render,
    ):
        PwnRequestVisitor.find_pwn_requests(mock_graph, mock_api)
        mock_process.assert_called_once()
        mock_render.assert_called()
