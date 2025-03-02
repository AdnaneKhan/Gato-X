import pytest
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED, Future

from gatox.models.repository import Repository

from gatox.enumerate.deep_dive.ingest_non_default import IngestNonDefault

# FILE: gatox/enumerate/deep_dive/test_ingest_non_default.py


@pytest.fixture
def mock_repo():
    repo = Mock(spec=Repository)
    repo.name = "test/repo"
    return repo


@pytest.fixture
def mock_api():
    api = Mock()
    api.pat = "test_pat"
    return api


@patch("gatox.enumerate.deep_dive.ingest_non_default.ThreadPoolExecutor")
def test_ingest_initializes_executor(mock_executor, mock_repo, mock_api):
    IngestNonDefault._executor = None
    IngestNonDefault._api = None
    IngestNonDefault._futures = []

    IngestNonDefault.ingest(mock_repo, mock_api)

    mock_executor.assert_called_once_with(max_workers=8)
    assert IngestNonDefault._api == mock_api


@patch("gatox.enumerate.deep_dive.ingest_non_default.ThreadPoolExecutor")
def test_ingest_submits_task(mock_executor, mock_repo, mock_api):
    mock_executor_instance = mock_executor.return_value
    mock_future = Mock(spec=Future)
    mock_executor_instance.submit.return_value = mock_future

    IngestNonDefault._executor = None
    IngestNonDefault._api = None
    IngestNonDefault._futures = []

    future = IngestNonDefault.ingest(mock_repo, mock_api)

    mock_executor_instance.submit.assert_called_once_with(
        IngestNonDefault._process_repo, mock_repo
    )
    assert future == mock_future
    assert future in IngestNonDefault._futures


@patch("gatox.enumerate.deep_dive.ingest_non_default.Git")
@patch("gatox.enumerate.deep_dive.ingest_non_default.WorkflowGraphBuilder")
def test_process_repo(mock_builder, mock_git, mock_repo, mock_api):
    mock_git_instance = mock_git.return_value
    mock_workflow = Mock()
    mock_git_instance.get_non_default.return_value = [mock_workflow]

    IngestNonDefault._api = mock_api
    IngestNonDefault._process_repo(mock_repo)

    mock_git.assert_called_once_with(mock_api.pat, mock_repo.name)
    mock_git_instance.get_non_default.assert_called_once()
    mock_builder.return_value.build_graph_from_yaml.assert_called_once_with(
        mock_workflow, mock_repo
    )


@patch("gatox.enumerate.deep_dive.ingest_non_default.wait")
def test_pool_empty_no_executor(mock_wait):
    IngestNonDefault._executor = None
    future = IngestNonDefault.pool_empty()

    assert future.done()
    assert future.result() is None
    mock_wait.assert_not_called()


@patch("gatox.enumerate.deep_dive.ingest_non_default.wait")
def test_pool_empty_with_executor(mock_wait):
    mock_future = Mock(spec=Future)
    mock_wait.return_value = ([], [mock_future])

    IngestNonDefault._executor = Mock()
    IngestNonDefault._futures = [mock_future]

    future = IngestNonDefault.pool_empty()

    mock_wait.assert_called_once_with([mock_future], return_when=ALL_COMPLETED)
    assert future.done()
    assert future.result() is None
