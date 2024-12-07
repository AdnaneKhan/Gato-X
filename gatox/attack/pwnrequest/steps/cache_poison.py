from gatox.attack.pwnrequest.steps.attack_step import AttackStep


class CachePoison(AttackStep):
    """Attack template that automates GitHub Actions cache poisoning
    after obtaining execution within a default branch workflow.
    """

    def __init__(self, payload_path: str):
        """ 
        """
        self.poison_payload = payload_path

    def setup(self, api):
        """ 
        """
        # Check that the files exist

        # Prepare the poisoned payload
        
        return True

    @AttackStep.require_params("cache_token", "cache_url")
    def preflight(self, cache_token=None, cache_url=None):
        """Validates preconditions for executing this step."""

        # Check that the cache JWT is valid by trying to read a value from the cache.

        # Check that the cache entries we want to write are vacated.

        pass

    def execute(self, api):
        """ """

        # If we have a actions: write credential, purge the cache key we want to 
        # poison with it.

        # Confirm successful purge of the cache key.

        # Upload the payload to the cache.

        # Confirm that we get a 204.
        
        return True