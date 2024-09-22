import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
from gatox.cli.output import Output


class DataIngestor:
    """Utility methods for performing parallel ingestion of data
    from GitHub using threadpools and GraphQL.
    """

    __counter = 0
    __lock = threading.Lock()
    __rl_lock = threading.Lock()

    @classmethod
    def update_count(cls, batch: int):
        """
        Update the class-level counter if the provided batch number is greater than the current counter.

        Args:
            batch (int): The batch number to compare with the current counter.

        Returns:
            None
        """
        with cls.__lock:
            if batch > cls.__counter:
                cls.__counter = batch

    @classmethod
    def check_status(cls):
        """This method returns the value of the class variable __counter."""
        return cls.__counter

    @classmethod
    def perform_parallel_repo_ingest(cls, api, org, repo_count):
        """
        Perform a parallel query of repositories up to the count within a given organization.

        Args:
            api (object): The API client used to make the GET requests.
            org (str): The organization name to query repositories from.
            repo_count (int): The number of repositories to query.

        Returns:
            list: A list of repositories retrieved from the organization.
        """
        repos = []

        def make_query(increment):
            """
            Makes a query to retrieve repositories for a given page.
            Attempts up to 5 times if the request fails.

            Args:
                increment (int): The page number to query.

            Returns:
                list: A list of repositories for the given page, or None if the query fails.
            """
            get_params = {"type": "public", "per_page": 100, "page": increment}

            sleep_timer = 4
            for _ in range(0, 5):
                repos = api.call_get(f"/orgs/{org}/repos", params=get_params)
                if repos.status_code == 200:
                    return repos.json()
                else:
                    time.sleep(sleep_timer)
                    sleep_timer = sleep_timer * 2
            Output.error("Unable to query. Will miss repositories.")

        batches = (repo_count // 100) + 1

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for batch in range(1, batches + 1):
                futures.append(executor.submit(make_query, batch))
            for future in as_completed(futures):
                listing = future.result()
                if listing:
                    repos.extend([repo for repo in listing if not repo["archived"]])

        return repos

    @classmethod
    def perform_query(cls, api, work_query, batch):
        """
        Performs a GraphQL query of repositories with up to 3 attempts, increasing the sleep timer from 4, 8, and then finally 16 seconds.

        Args:
            api (object): The API client used to make the POST requests.
            work_query (dict): The GraphQL query to be executed.
            batch (int): The batch number for which the query is being performed.

        Returns:
            list or dict: The nodes or values from the query result if successful, otherwise None.

        Raises:
            Exception: If an error occurs during the query execution.
        """
        try:
            for _ in range(0, 4):
                # We lock if another thread is sleeping due to a rate limit
                # but if no other thread is sleeping, we want to move on
                # to query.
                while cls.__rl_lock.locked():
                    time.sleep(0.1)

                result = api.call_post("/graphql", work_query)
                # Sometimes we don't get a 200, fall back in this case.
                if result.status_code == 200:
                    json_res = result.json()["data"]
                    DataIngestor.update_count(batch)
                    if "nodes" in json_res:
                        return result.json()["data"]["nodes"]
                    else:
                        return result.json()["data"].values()
                elif result.status_code == 403:
                    with cls.__rl_lock:
                        time.sleep(15 + random.randint(0, 3))
                else:
                    # Add some jitter
                    time.sleep(10 + random.randint(0, 3))

            Output.warn(
                f"GraphQL attempts failed for batch {str(batch)}, will revert to REST for impacted repos."
            )
        except Exception as e:
            Output.warn(
                "Exception while running GraphQL query, will revert to REST "
                "API workflow query for impacted repositories!"
            )
            print(e)

    @staticmethod
    def construct_workflow_cache(yml_results):
        """
        Creates a cache of workflow YAML files retrieved from GraphQL. Since GraphQL and REST do not have parity,
        REST is still used for most enumeration calls. This method saves all YAML files, so during organization-level
        enumeration, if YAML enumeration is performed, the cached file is used instead of making GitHub REST requests.

        Args:
            yml_results (list): List of results from individual GraphQL queries (100 nodes at a time).

        Returns:
            None
        """
        if yml_results is None:
            return

        cache = CacheManager()
        for result in yml_results:
            # If we get any malformed/missing data just skip it and
            # Gato will fall back to the contents API for these few cases.
            if not result:
                continue

            if "nameWithOwner" not in result:
                continue

            owner = result["nameWithOwner"]
            cache.set_empty(owner)
            # Empty means no YAMLs, so just skip.
            if result["object"]:
                for yml_node in result["object"]["entries"]:
                    yml_name = yml_node["name"]
                    if yml_node["type"] == "blob" and (
                        yml_name.lower().endswith("yml")
                        or yml_name.lower().endswith("yaml")
                    ):
                        if "text" in yml_node["object"]:
                            contents = yml_node["object"]["text"]
                            wf_wrapper = Workflow(owner, contents, yml_name)

                            cache.set_workflow(owner, yml_name, wf_wrapper)

            # If we are using app installation tokens, then
            # the query might return empty for this field, but if
            # we are here then we can read.
            if not result["viewerPermission"]:
                result["viewerPermission"] = "READ"

            repo_data = {
                "full_name": result["nameWithOwner"],
                "html_url": result["url"],
                "visibility": "private" if result["isPrivate"] else "public",
                "default_branch": (
                    result["defaultBranchRef"]["name"]
                    if result["defaultBranchRef"]
                    else "main"
                ),
                "fork": result["isFork"],
                "stargazers_count": result["stargazers"]["totalCount"],
                "pushed_at": result["pushedAt"],
                "permissions": {
                    "pull": result["viewerPermission"] == "READ"
                    or result["viewerPermission"] == "TRIAGE"
                    or result["viewerPermission"] == "WRITE"
                    or result["viewerPermission"] == "MAINTAIN"
                    or result["viewerPermission"] == "ADMIN",
                    "push": result["viewerPermission"] == "WRITE"
                    or result["viewerPermission"] == "MAINTAIN"
                    or result["viewerPermission"] == "ADMIN",
                    "maintain": result["viewerPermission"] == "MAINTAIN"
                    or result["viewerPermission"] == "ADMIN",
                    "admin": result["viewerPermission"] == "ADMIN",
                },
                "archived": result["isArchived"],
                "isFork": result["isFork"],
                "allow_forking": result["forkingAllowed"],
                "environments": [],
            }

            if "environments" in result and result["environments"]:
                # Capture environments not named github-pages
                envs = [
                    env["node"]["name"]
                    for env in result["environments"]["edges"]
                    if env["node"]["name"] != "github-pages"
                ]
                repo_data["environments"] = envs
            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)
