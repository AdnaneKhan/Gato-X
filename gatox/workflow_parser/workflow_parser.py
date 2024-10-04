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

import logging

from pathlib import Path
import os

from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.workflow_parser.utility import filter_tokens, decompose_action_ref
from gatox.workflow_parser.components.job import Job
from gatox.models.workflow import Workflow

logger = logging.getLogger(__name__)


class WorkflowParser:
    """Parser for YML files.

    This class is structurd to take a yaml file as input, it will then
    expose methods that aim to answer questions about the yaml file.

    This will allow for growing what kind of analytics this tool can perform
    as the project grows in capability.

    This class should only perform static analysis. The caller is responsible for
    performing any API queries to augment the analysis.
    """

    def __init__(self, workflow_wrapper: Workflow, non_default=None):
        """Initialize class with workflow file.

        Args:
            workflow_yml (str): String containing yaml file read in from
            repository.
            repo_name (str): Name of the repository.
            workflow_name (str): name of the workflow file
        """
        if workflow_wrapper.isInvalid():
            raise ValueError("Received invalid workflow!")

        self.parsed_yml = workflow_wrapper.parsed_yml

        if "jobs" in self.parsed_yml and self.parsed_yml["jobs"] is not None:
            self.jobs = [
                Job(job_data, job_name)
                for job_name, job_data in self.parsed_yml.get("jobs", []).items()
            ]
        else:
            self.jobs = []
        self.raw_yaml = workflow_wrapper.workflow_contents
        self.repo_name = workflow_wrapper.repo_name
        self.wf_name = workflow_wrapper.workflow_name
        self.callees = []
        self.sh_callees = []
        self.external_ref = False

        if workflow_wrapper.special_path:
            self.external_ref = True
            self.external_path = workflow_wrapper.special_path
            self.branch = workflow_wrapper.branch
        elif non_default:
            self.branch = non_default
        else:
            self.branch = workflow_wrapper.branch
    

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.

        Args:
            dirpath (str): Directory to save the yaml file to.

        Returns:
            bool: Whether the file was successfully written.
        """
        Path(os.path.join(dirpath, f"{self.repo_name}")).mkdir(
            parents=True, exist_ok=True
        )

        with open(
            os.path.join(dirpath, f"{self.repo_name}/{self.wf_name}"), "w"
        ) as wf_out:
            wf_out.write(self.raw_yaml)
            return True

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners.

        Returns:
           list: List of jobs within the workflow that utilize self-hosted
           runners.
        """
        sh_jobs = []

        for job in self.jobs:
            if job.isSelfHosted():
                sh_jobs.append((job.job_name, job.job_data))
            elif job.isCaller():
                if job.external_caller:
                    self.sh_callees.append(job.uses)
                else:
                    self.sh_callees.append(job.uses.split("/")[-1])

        return sh_jobs
