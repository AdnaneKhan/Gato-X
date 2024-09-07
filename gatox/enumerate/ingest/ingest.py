import time
import random
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait, as_completed

from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository
from gatox.cli.output import Output

class DataIngestor:

    @staticmethod
    def perform_parallel_repo_ingest(api, org, repo_count):
        """Perform a parallel query of repositories up to the count
        within a given organization.
        """
        repos = []

        def make_query(increment):
            """Makes query to retrieve repos for given page.
            Attempts up to 5 times.
            """
            get_params = {
                "type": "public",
                "per_page": 100,
                "page": increment
            }

            sleep_timer = 4
            for i in range (0, 5):
                repos = api.call_get(f'/orgs/{org}/repos', params=get_params)
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
                    repos.extend([repo for repo in listing if not repo['archived']])

        return repos

    @staticmethod
    def perform_query(api, work_query, batch):
        """Performs GraphQL query of repositories. Gato-X will use 3
        attempts, increasing the sleep timer from 4, 8, and then finally 16 
        seconds.
        """
        try:
            for i in range (0, 4):
                result = api.call_post('/graphql', work_query)
                # Sometimes we don't get a 200, fall back in this case.
                if result.status_code == 200:
                    json_res = result.json()['data']
                    if 'nodes' in json_res:
                        return result.json()['data']['nodes']
                    else:
                        return result.json()['data'].values()
                    break
                elif result.status_code == 403:
                    Output.warn(
                        f"GraphQL query batch {str(batch)} hit secondary rate limit on attempt"
                        f" {str(i+1)}!"
                    )
                    time.sleep(15 + random.randint(0,3))
                else:
                    Output.warn(
                        f"GraphQL query batch {str(batch)} failed with {result.status_code} "
                        f"on attempt {str(i+1)}!")
                    # Add some jitter
                    time.sleep(10 + random.randint(0,3))
           
            Output.warn("GraphQL attempts failed, will revert to REST for impacted repos.")
        except Exception as e:
            Output.warn(
                "Exception while running GraphQL query, will revert to REST "
                "API workflow query for impacted repositories!"
            )
            print(e)

    @staticmethod
    def construct_workflow_cache(yml_results):
        """Creates a cache of workflow yml files retrieved from graphQL. Since
        graphql and REST do not have parity, we still need to use rest for most
        enumeration calls. This method saves off all yml files, so during org
        level enumeration if we perform yml enumeration the cached file is used
        instead of making github REST requests. 

        Args:
            yml_results (list): List of results from individual GraphQL queries
            (100 nodes at a time).
        """
        if yml_results is None:
            return

        cache = CacheManager()
        for result in yml_results:
            # If we get any malformed/missing data just skip it and 
            # Gato will fall back to the contents API for these few cases.
            if not result:
                continue
                
            if 'nameWithOwner' not in result:
                continue

            owner = result['nameWithOwner']
            cache.set_empty(owner)
            # Empty means no yamls, so just skip.
            if result['object']:
                for yml_node in result['object']['entries']:
                    yml_name = yml_node['name']      
                    if yml_node['type'] == 'blob' and \
                      (yml_name.lower().endswith('yml') \
                      or yml_name.lower().endswith('yaml')): 
                        if 'text' in yml_node['object']:
                            contents = yml_node['object']['text']
                            wf_wrapper = Workflow(owner, contents, yml_name)
                            
                            cache.set_workflow(owner, yml_name, wf_wrapper) 

            repo_data = {
                'full_name': result['nameWithOwner'],
                'html_url': result['url'],
                'visibility': 'private' if result['isPrivate'] else 'public',
                'default_branch': result['defaultBranchRef']['name'] if result['defaultBranchRef'] else 'main',
                'fork': result['isFork'],
                'stargazers_count': result['stargazers']['totalCount'],
                'pushed_at': result['pushedAt'],
                'permissions': {
                    'pull': result['viewerPermission'] == 'READ' or \
                      result['viewerPermission'] == 'TRIAGE' or \
                      result['viewerPermission'] == 'WRITE' or \
                      result['viewerPermission'] == 'MAINTAIN' or \
                      result['viewerPermission'] == 'ADMIN',
                    'push': result['viewerPermission'] == 'WRITE' or \
                        result['viewerPermission'] == 'MAINTAIN' or \
                        result['viewerPermission'] == 'ADMIN',
                    'maintain': result['viewerPermission'] == 'MAINTAIN' or \
                        result['viewerPermission'] == 'ADMIN',
                    'admin': result['viewerPermission'] == 'ADMIN'
                },
                'archived': result['isArchived'],
                'isFork': result['isFork'],
                'allow_forking': result['forkingAllowed'],
                'environments': []
            }

            if 'environments' in result and result['environments']:
                # Capture environments not named github-pages
                envs = [env['node']['name']  for env in result['environments']['edges'] if env['node']['name'] != 'github-pages']
                repo_data['environments'] = envs
                    
            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)
