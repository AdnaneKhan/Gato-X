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

import logging

from gatox.caching.cache_manager import CacheManager
from gatox.workflow_graph.graph.tagged_graph import TaggedGraph

logger = logging.getLogger(__name__)


class RunnerVisitor:
    """Simple visitor that extracts nodes that are tagged to potentially
    run on self-hosted runners.
    """

    @staticmethod
    def find_runner_workflows(graph: TaggedGraph):
        """Graph visitor to find workflows that are likely
        to use self-hosted runners.
        """
        nodes = graph.get_nodes_for_tags(["self-hosted"])
        workflows = {}
        for node in nodes:
            try:
                repo = node.repo_name()

                if "workflow_call" in node.get_workflow().get_tags():
                    # We need to find the parent workflow.
                    callers = node.get_workflow().get_caller_workflows()
                    for caller in callers:
                        workflows.setdefault(repo, set()).add(
                            caller.get_workflow_name()
                        )

                cached_repo = CacheManager().get_repository(repo)
                if cached_repo:
                    cached_repo.add_self_hosted_workflows([node.get_workflow_name()])

                workflows.setdefault(repo, set()).add(node.get_workflow_name())
            except Exception as e:
                logger.warning(f"Error processing node: {node.name}")
                logger.warning(e)

        return workflows
