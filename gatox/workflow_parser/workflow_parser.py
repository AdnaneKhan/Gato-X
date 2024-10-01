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
import re

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
            self.branch = None

        self.composites = self.extract_referenced_actions()

    def is_referenced(self):
        return self.external_ref

    def has_trigger(self, trigger):
        """Check if the workflow has a specific trigger.

        Args:
            trigger (str): The trigger to check for.
        Returns:
            bool: Whether the workflow has the specified trigger.
        """
        return self.get_vulnerable_triggers(trigger)

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

    def extract_referenced_actions(self):
        """
        Extracts composite actions from the workflow file.
        """
        referenced_actions = {}
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers:
            return referenced_actions

        if "jobs" not in self.parsed_yml:
            return referenced_actions

        for job in self.jobs:
            for step in job.steps:
                # Local action referenced
                if step.type == "ACTION":
                    action_parts = decompose_action_ref(
                        step.uses, step.step_data, self.repo_name
                    )
                    # Save off by uses as key
                    if action_parts:
                        referenced_actions[step.uses] = action_parts

        return referenced_actions

    def get_vulnerable_triggers(self, alternate=False):
        """Analyze if the workflow is set to execute on potentially risky triggers.

        Returns:
            list: List of triggers within the workflow that could be vulnerable
            to GitHub Actions script injection vulnerabilities.
        """
        vulnerable_triggers = []
        risky_triggers = [
            "pull_request_target",
            "workflow_run",
            "issue_comment",
            "issues",
            "discussion_comment",
            "discussion" "fork",
            "watch",
        ]
        if alternate:
            risky_triggers = [alternate]

        if not self.parsed_yml or "on" not in self.parsed_yml:
            return vulnerable_triggers
        triggers = self.parsed_yml["on"]
        if isinstance(triggers, list):
            for trigger in triggers:
                if trigger in risky_triggers:
                    vulnerable_triggers.append(trigger)
        elif isinstance(triggers, str):
            if triggers in risky_triggers:
                vulnerable_triggers.append(triggers)
        elif isinstance(triggers, dict):
            for trigger, trigger_conditions in triggers.items():
                if trigger in risky_triggers:
                    if trigger_conditions and "types" in trigger_conditions:
                        if (
                            "labeled" in trigger_conditions["types"]
                            and len(trigger_conditions["types"]) == 1
                        ):
                            vulnerable_triggers.append(
                                f"{trigger}:{trigger_conditions['types'][0]}"
                            )
                        else:
                            vulnerable_triggers.append(trigger)
                    else:
                        vulnerable_triggers.append(trigger)

        return vulnerable_triggers

    def backtrack_gate(self, needs_name):
        """Attempts to find if a job needed by a specific job has a gate check."""
        if type(needs_name) is list:
            for need in needs_name:
                if self.backtrack_gate(need):
                    return True
            return False
        else:
            for job in self.jobs:
                if job.job_name == needs_name and job.gated():
                    return True
                # If the job it needs does't have a gate, then check if it does.
                elif job.job_name == needs_name and not job.gated():
                    return self.backtrack_gate(job.needs)
        return False

    def analyze_checkouts(self):
        """Analyze if any steps within the workflow utilize the
        'actions/checkout' action with a 'ref' parameter.

        Returns:
            job_checkouts: List of 'ref' values within the 'actions/checkout' steps.
        """
        job_checkouts = {}
        if "jobs" not in self.parsed_yml:
            return job_checkouts

        for job in self.jobs:
            job_content = {
                "check_steps": [],
                "if_check": job.evaluateIf(),
                "confidence": "UNKNOWN",
                "gated": False,
            }
            step_details = []
            bump_confidence = False

            if job.isCaller():
                self.callees.append(job.uses.split("/")[-1])
            elif job.external_caller:
                self.callees.append(job.uses)

            if job_content["if_check"] and job_content["if_check"].startswith(
                "RESTRICTED"
            ):
                job_content["gated"] = True

            for step in job.steps:
                # If the step is a gate, exit now, we can't reach the rest of the job.
                if step.is_gate:
                    job_content["gated"] = True
                elif step.is_checkout:
                    # Check if the dependant jobs are gated.
                    if job.needs:
                        job_content["gated"] = self.backtrack_gate(job.needs)
                    # If the step is a checkout and the ref is pr sha, then no TOCTOU is possible.
                    if job_content["gated"] and (
                        "github.event.pull_request.head.sha" in step.metadata.lower()
                        or (
                            "sha" in step.metadata.lower()
                            and "env." in step.metadata.lower()
                        )
                    ):
                        # Break out of this job.
                        break
                    else:
                        if_check = step.evaluateIf()
                        if if_check and if_check.startswith("EVALUATED"):
                            bump_confidence = True
                        elif if_check and "RESTRICTED" in if_check:
                            # In the future, we will exit here.
                            bump_confidence = False
                        elif if_check == "":
                            pass

                        step_details.append(
                            {
                                "ref": step.metadata,
                                "if_check": if_check,
                                "step_name": step.name,
                            }
                        )

                elif step_details and step.is_sink:
                    # Confirmed sink, so set to HIGH if reachable via expression parser or no check at all
                    job_content["confidence"] = (
                        "HIGH"
                        if (
                            job_content["if_check"]
                            and job_content["if_check"].startswith("EVALUATED")
                        )
                        or (bump_confidence and not job_content["if_check"])
                        or (
                            not job_content["if_check"]
                            and (
                                not step.evaluateIf()
                                or step.evaluateIf().startswith("EVALUATED")
                            )
                        )
                        else "MEDIUM"
                    )

            job_content["check_steps"] = step_details
            job_checkouts[job.job_name] = job_content

        return job_checkouts

    def check_pwn_request(self, bypass=False):
        """Check for potential pwn request vulnerabilities.

        Returns:
            dict: A dictionary containing the job names as keys and a
            list of potentially vulnerable tokens as values.
        """

        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            return {}

        checkout_risk = {}
        candidates = {}

        checkout_info = self.analyze_checkouts()
        for job_name, job_content in checkout_info.items():

            steps_risk = job_content["check_steps"]
            if steps_risk:

                candidates[job_name] = {}
                candidates[job_name]["confidence"] = job_content["confidence"]
                candidates[job_name]["gated"] = job_content["gated"]
                candidates[job_name]["steps"] = steps_risk
                if "if_check" in job_content and job_content["if_check"]:
                    candidates[job_name]["if_check"] = job_content["if_check"]
                else:
                    candidates[job_name]["if_check"] = ""

        if candidates:
            checkout_risk["candidates"] = candidates
            checkout_risk["triggers"] = vulnerable_triggers

        return checkout_risk

    def check_rules(self, gate_rules):
        """Checks environment protection rules from the API against those specified in the job.

        Args:
            gate_rules (list): List of rules to check against.

        Returns:
            bool: Whether the job is violating any of the rules.
        """
        for rule in gate_rules:
            for job in self.jobs:
                for deploy_rule in job.deployments:
                    if rule in deploy_rule:
                        return False
        return True

    def check_injection(self, bypass=False):
        """Check for potential script injection vulnerabilities.

        Returns:
            dict: A dictionary containing the job names as keys and a list
            of potentially vulnerable tokens as values.
        """
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers and not bypass:
            return {}

        injection_risk = {}

        for job in self.jobs:

            for step in job.steps:
                # No TOCTOU possible for injection

                if step.is_gate:
                    break

                # Check if we marked the step as being an injectable script of some kind.
                if step.is_script:
                    tokens = step.getTokens()
                else:
                    continue
                tokens = filter_tokens(tokens)

                def check_token(token, container):
                    if (
                        token.startswith("env.")
                        and token.split(".")[1] in container["env"]
                    ):
                        value = container["env"][token.split(".")[1]]

                        if value and type(value) not in [int, float] and "${{" in value:
                            return True
                        else:
                            return False
                    return True

                # Remove tokens that map to workflow or job level environment variables, as
                # these will not be vulnerable to injection unless they reference
                # something by context expression.
                env_sources = [self.parsed_yml, job.job_data, step.step_data]
                for env_source in env_sources:
                    if "env" in env_source and tokens:
                        tokens = [
                            token for token in tokens if check_token(token, env_source)
                        ]

                if tokens:
                    if job.needs and self.backtrack_gate(job.needs):
                        break

                    if job.job_name not in injection_risk:
                        injection_risk[job.job_name] = {}
                        injection_risk[job.job_name]["if_check"] = job.evaluateIf()

                    injection_risk[job.job_name][step.name] = {
                        "variables": list(set(tokens))
                    }
                    if step.evaluateIf():
                        injection_risk[job.job_name][step.name][
                            "if_checks"
                        ] = step.evaluateIf()
        if injection_risk:
            injection_risk["triggers"] = vulnerable_triggers

        return injection_risk

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
