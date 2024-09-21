import unittest
from unittest.mock import MagicMock
from gatox.enumerate.ingest.ingest import DataIngestor
from gatox.caching.cache_manager import CacheManager


class TestConstructWorkflowCache(unittest.TestCase):

    def setUp(self):
        self.workflow = MagicMock()
        self.repository = MagicMock()
        CacheManager._instance = None
        self.cache_manager = CacheManager()
        Workflow = MagicMock(return_value=self.workflow)
        Repository = MagicMock(return_value=self.repository)
        self.yml_results = [
            {
                "nameWithOwner": "owner/repo1",
                "object": {
                    "entries": [
                        {
                            "name": "workflow1.yml",
                            "type": "blob",
                            "object": {"text": "content1"},
                        }
                    ]
                },
                "url": "http://example.com/repo1",
                "isPrivate": False,
                "defaultBranchRef": {"name": "main"},
                "isFork": False,
                "stargazers": {"totalCount": 10},
                "pushedAt": "2023-01-01T00:00:00Z",
                "viewerPermission": "ADMIN",
                "isArchived": False,
                "forkingAllowed": True,
                "environments": {"edges": []},
            }
        ]

    def test_construct_workflow_cache_none(self):
        # Test with None input
        assert DataIngestor.construct_workflow_cache(None) is None

    def test_construct_workflow_cache_empty_list(self):
        # Test with empty list input
        DataIngestor.construct_workflow_cache([])

        assert CacheManager()._instance.repo_wf_lookup == {}
        assert CacheManager()._instance.workflow_cache == {}

    def test_construct_workflow_cache_valid_input(self):
        # Test with valid input
        DataIngestor.construct_workflow_cache(self.yml_results)

        assert CacheManager().is_repo_cached("owner/repo1") is True

    def test_construct_workflow_cache_malformed_data(self):
        # Test with malformed data
        malformed_data = [{"invalid_key": "invalid_value"}]
        DataIngestor.construct_workflow_cache(malformed_data)

        assert not CacheManager().is_repo_cached("invalid_key")


if __name__ == "__main__":
    unittest.main()
