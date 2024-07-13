from gatox.caching.cache_manager import CacheManager
from gatox.models.workflow import Workflow
from gatox.models.repository import Repository

class DataIngestor:

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
                    if yml_name.lower().endswith('yml') or yml_name.lower().endswith('yaml'):
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
                        result['viewerPermission'] == 'ADMIN',
                    'admin': result['viewerPermission'] == 'ADMIN'
                },
                'archived': result['isArchived'],
                'isFork': result['isFork'],
                'environments': []
            }

            if 'environments' in result and result['environments']:
                # Capture environments not named github-pages
                envs = [env['node']['name']  for env in result['environments']['edges'] if env['node']['name'] != 'github-pages']
                repo_data['environments'] = envs
                    
            repo_wrapper = Repository(repo_data)
            cache.set_repository(repo_wrapper)
