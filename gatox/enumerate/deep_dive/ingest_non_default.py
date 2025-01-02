import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
from gatox.workflow_graph.graph_builder import WorkflowGraphBuilder
from gatox.cli.output import Output
from gatox.git.git import Git


class IngestNonDefault:
    """Class to handle ingesting non-default branches."""

    @staticmethod
    def ingest(repo: Repository, api):
        """Ingests non-default branch pull request target workflows."""
        git_client = Git(
            api.pat,
            repo.name,
        )

        workflows = git_client.get_non_default()

        for workflow in workflows:
            WorkflowGraphBuilder().build_graph_from_yaml(workflow, repo)
