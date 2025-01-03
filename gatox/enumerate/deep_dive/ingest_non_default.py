import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, ALL_COMPLETED

from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.cli.output import Output
from gatox.git.git import Git


class IngestNonDefault:
    """Class to handle ingesting non-default branches with a thread pool."""

    _executor = None
    _api = None
    _futures = []

    @classmethod
    def ingest(cls, repo: Repository, api):
        """
        Enqueue a repository ingest task into the worker pool.
        If the pool and API haven't been initialized, initialize them.
        """
        if cls._executor is None:
            cls._executor = ThreadPoolExecutor(max_workers=8)
        if cls._api is None:
            cls._api = api

        # Submit a repository processing job
        future = cls._executor.submit(cls._process_repo, repo)
        cls._futures.append(future)
        return future

    @classmethod
    def _process_repo(cls, repo: Repository):
        """Actual processing of a repository's non-default workflows."""
        git_client = Git(cls._api.pat, repo.name)
        workflows = git_client.get_non_default()
        for workflow in workflows:
            WorkflowGraphBuilder().build_graph_from_yaml(workflow, repo)

    @classmethod
    def pool_empty(cls):
        """
        Returns a Future that completes once all currently-enqueued tasks finish.
        This method blocks until all tasks are done, then returns a completed Future.
        """
        if cls._executor is None:
            # No work was ever queued
            from concurrent.futures import Future

            f = Future()
            f.set_result(None)
            return f

        done, not_done = wait(cls._futures, return_when=ALL_COMPLETED)
        # Create a new completed Future to return
        from concurrent.futures import Future

        final_future = Future()
        final_future.set_result(None)
        return final_future
