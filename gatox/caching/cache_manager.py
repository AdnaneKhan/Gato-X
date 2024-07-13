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
    Singleton class that manages an in-memory cache.

    TODO: Integrate with Redis.
    """
    _instance = None

    def __getstate__(self):
        state = self.__dict__.copy()
        # Remove the unpicklable entries.
        state['_instance'] = None
        return state

    def __setstate__(self, state):
        # Restore instance attributes
        self.__dict__.update(state)
        # Restore the singleton instance
        self._instance = self

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
        key = f"{repo_slug}:{workflow_name}"
        return self.workflow_cache.get(key, None)
        
    def is_repo_cached(self, repo_slug: str):
        """
        Check if a repository is in the in-memory dictionary.
        """
        return repo_slug in self.repo_wf_lookup
        
    def get_workflows(self, repo_slug: str):
        """
        Get all workflows for a repository from the in-memory dictionary.
        """
        wf_keys = self.repo_wf_lookup.get(repo_slug, None)
        if wf_keys:
            return [self.workflow_cache[f"{repo_slug}:{key}"] for key in wf_keys]
        else:
            return set()

    def get_action(self, repo_slug: str, action_path: str):
        """
        Get an action from the in-memory dictionary.
        """
        key = f"{repo_slug}:{action_path}"
        return self.action_cache.get(key, None)
        
    def set_repository(self, repository: Repository):
        """
        Set a repository in the in-memory dictionary.
        """
        key = repository.name
        self.repo_store[key] = repository

    def get_repository(self, repo_slug: str):
        """
        Get a repository from the in-memory dictionary.
        """
        return self.repo_store.get(repo_slug, None)

    def set_workflow(self, repo_slug: str, workflow_name: str, value: Workflow):
        """
        Set a workflow in the in-memory dictionary.
        """
        key = f"{repo_slug}:{workflow_name}"
        if repo_slug not in self.repo_wf_lookup:
            self.repo_wf_lookup[repo_slug] = set()
        self.repo_wf_lookup[repo_slug].add(workflow_name)
        self.workflow_cache[key] = value

    def set_empty(self, repo_slug: str):
        """
        Set an empty value in the in-memory dictionary for a repository.
        """
        self.repo_wf_lookup[repo_slug] = set()

    def set_action(self, repo_slug: str, action_path: str, value: str):
        """
        Set an action in the in-memory dictionary.
        """
        key = f"{repo_slug}:{action_path}"
        self.action_cache[key] = value