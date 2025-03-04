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

from gatox.workflow_graph.graph.tagged_graph import TaggedGraph
from gatox.github.api import Api


def ArtifactPoisoningVisitor():
    """Visits the graph to find potential artifact poisoning vulnerabilities.

    This is where the workflow runs on workflow_run, then downloads an
    artifact, extracts it, and then runs code from it or uses values from it
    in an unsafe manner.
    """

    @staticmethod
    def find_artifact_poisoning(graph: TaggedGraph, api: Api):
        # Unlike pwn requests, we are looking specifically
        # for cases of improper aritfact validation,
        # so we follow different logic focused on that.
        # Now we have all reponodes
        nodes = graph.get_nodes_for_tags(["workflow_run"])

        all_paths = []

        for cn in nodes:
            paths = graph.dfs_to_tag(cn, "artifact", api)
            if paths:
                all_paths.append(paths)
