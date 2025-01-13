import json

from gatox.caching.cache_manager import CacheManager

class LocalCacheFactory:
    """
    """

    @staticmethod
    def dump_cache(output_file: str):
        """
        Dump the cache to a file.

        Args:
            output_file (str): The file to write the cache to.
        """

        with open(output_file, "w") as f:
            CacheManager().serialize_full_cache(f)

    @staticmethod
    def load_cache_from_file(saved_cache: str):
        """
        """
        with open(saved_cache, "r") as f:
            data = json.load(f)
            for key, val in data.items():
                parts = key.split(":")
                if len(parts) != 3:
                    raise ValueError(f"Invalid cache key format '{key}'. Expected 'repo_slug:action_path:ref'.")
                if parts[0] != parts[0].lower():
                    raise ValueError(f"Repository slug '{parts[0]}' must be lowercase.")

                repo_slug, action_path, ref = parts
                CacheManager().set_action(repo_slug, action_path, ref, val)