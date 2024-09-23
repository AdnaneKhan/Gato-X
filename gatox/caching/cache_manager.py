"""
Copyright 2024, Adnan Khan

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

from gatox.models.workflow import Workflow
from gatox.models.repository import Repository


class CacheManager:
    """
    Singleton class that manages an in-memory cache for workflows and reusable actions.

    TODO: Integrate with Redis.
    """

    _instance = None

    def __new__(cls):
        """
        Create a new instance of the class. If an instance already exists, return that instance.
        """
        if cls._instance is None:
            cls._instance = super(CacheManager, cls).__new__(cls)
            cls._instance.repo_wf_lookup = {}
            cls._instance.repo_store = {}
            cls._instance.workflow_cache = {}
            cls._instance.action_cache = {}
        return cls._instance

    def get_workflow(self, repo_slug: str, workflow_name: str):
        """
        Get a workflow from the in-memory dictionary.
        """
        key = f"{repo_slug.lower()}:{workflow_name}"
        return self.workflow_cache.get(key, None)

    def is_repo_cached(self, repo_slug: str):
        """
        Check if a repository is in the in-memory dictionary.
        """
        return repo_slug.lower() in self.repo_wf_lookup

    def is_action_cached(self, repo_slug: str, action_path: str, ref: str):
        """
        Check if action is cached.
        """
        key = f"{repo_slug.lower()}:{action_path}:{ref}"
        return key in self.action_cache

    def get_workflows(self, repo_slug: str):
        """
        Get all workflows for a repository from the in-memory dictionary.
        """
        wf_keys = self.repo_wf_lookup.get(repo_slug.lower(), None)
        if wf_keys:
            return [
                self.workflow_cache[f"{repo_slug.lower()}:{key}"] for key in wf_keys
            ]
        else:
            return set()

    def get_action(self, repo_slug: str, action_path: str, ref: str):
        """
        Get an action from the in-memory dictionary.
        """
        key = f"{repo_slug.lower()}:{action_path}:{ref}"
        return self.action_cache.get(key, None)

    def set_repository(self, repository: Repository):
        """
        Set a repository in the in-memory dictionary.
        """
        key = repository.name.lower()
        self.repo_store[key] = repository

    def get_repository(self, repo_slug: str):
        """
        Get a repository from the in-memory dictionary.
        """
        return self.repo_store.get(repo_slug.lower(), None)

    def set_workflow(self, repo_slug: str, workflow_name: str, value: Workflow):
        """
        Set a workflow in the in-memory dictionary.
        """
        key = f"{repo_slug.lower()}:{workflow_name}"
        if repo_slug.lower() not in self.repo_wf_lookup:
            self.repo_wf_lookup[repo_slug.lower()] = set()
        self.repo_wf_lookup[repo_slug.lower()].add(workflow_name)
        self.workflow_cache[key] = value

    def set_empty(self, repo_slug: str):
        """
        Set an empty value in the in-memory dictionary for a repository.
        """
        self.repo_wf_lookup[repo_slug.lower()] = set()

    def set_action(self, repo_slug: str, action_path: str, ref: str, value: str):
        """
        Set an action in the in-memory dictionary.
        """
        key = f"{repo_slug.lower()}:{action_path}:{ref}"
        self.action_cache[key] = value
