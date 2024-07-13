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

from gatox.github.api import Api

from gatox.attack.attack import Attacker

class LabelRaceAttack:
    """Uses the GitHub API to attempt to exploit a race condition for
    workflows that run on the 'pull_request_target' labeled event but
    check out the fork repository by:

    * The head ref (branch name) + repo name
    * The head merge ref + repo name

    This means that an attacker can update the PR head between the time the pull
    request is labeled and the workflow checks out + runs the code. This
    is not exploitable if the workflow checks out the head SHA included
    in the event payload directly.
    """

    def poll_label(label_name: str, api: Api, target_file: str, new_contents: bytes):
        """Polls for a label on a pull request and then updates the PR head
        to a different commit to exploit the race condition.
        """
        # First, poll for the label on the PR

        # Next, update the PR head to a different commit using the GitHub API
        raise NotImplementedError