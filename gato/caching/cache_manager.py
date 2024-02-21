import redis
from typing import Optional, Dict

class CacheManager:
    """
    Singleton class that manages a Redis cache or an in-memory cache.
    """
    _instance = None

    def __new__(cls, redis_config: Optional[Dict] = None):
        """
        Create a new instance of the class. If an instance already exists, return that instance.
        If a redis_config is provided, use Redis as the backing store. Otherwise, use in-memory dictionaries.
        """
        if cls._instance is None:
            cls._instance = super(CacheManager, cls).__new__(cls)
            cls._instance.workflow_cache = {}
            cls._instance.action_cache = {}
            if redis_config:
                cls._instance.redis_store = redis.Redis(host=redis_config['host'], port=redis_config['port'], db=redis_config['db'])
            else:
                cls._instance.redis_store = None
        return cls._instance

    def get_workflow(self, repo_slug: str, workflow_name: str):
        """
        Get a workflow from the cache.
        If Redis is being used, get the workflow from the Redis store.
        Otherwise, get the workflow from the in-memory dictionary.
        """
        key = f"{repo_slug}:{workflow_name}.yml"
        if self.redis_store:
            return self.redis_store.get(key)
        else:
            return self.workflow_cache.get(key, None)

    def get_action(self, repo_slug: str, action_path: str):
        """
        Get an action from the cache.
        If Redis is being used, get the action from the Redis store.
        Otherwise, get the action from the in-memory dictionary.
        """
        key = f"{repo_slug}:{action_path}"
        if self.redis_store:
            return self.redis_store.get(key)
        else:
            return self.action_cache.get(key, None)

    def set_workflow(self, repo_slug: str, workflow_name: str, value: str):
        """
        Set a workflow in the cache.
        If Redis is being used, set the workflow in the Redis store.
        Otherwise, set the workflow in the in-memory dictionary.
        """
        key = f"{repo_slug}:{workflow_name}.yml"
        if self.redis_store:
            self.redis_store.set(key, value)
        else:
            self.workflow_cache[key] = value

    def set_action(self, repo_slug: str, action_path: str, value: str):
        """
        Set an action in the cache.
        If Redis is being used, set the action in the Redis store.
        Otherwise, set the action in the in-memory dictionary.
        """
        key = f"{repo_slug}:{action_path}"
        if self.redis_store:
            self.redis_store.set(key, value)
        else:
            self.action_cache[key] = value