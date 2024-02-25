import logging
import yaml
from pathlib import Path
import os
import re

from gato.workflow_parser.utility import check_sus, process_steps

from yaml.resolver import Resolver

logger = logging.getLogger(__name__)

# remove resolver entries for On/Off/Yes/No
for ch in "OoTtFf":
    if len(Resolver.yaml_implicit_resolvers[ch]) == 1:
        del Resolver.yaml_implicit_resolvers[ch]
    else:
        Resolver.yaml_implicit_resolvers[ch] = [x for x in
        Resolver.yaml_implicit_resolvers[ch] if x[0] != 'tag:yaml.org,2002:bool']


class WorkflowParser():
    """Parser for YML files.

    This class is structurd to take a yaml file as input, it will then
    expose methods that aim to answer questions about the yaml file.

    This will allow for growing what kind of analytics this tool can perform
    as the project grows in capability.
    """

    UNSAFE_CONTEXTS = [
        'github.event.issue.title',
        'github.event.issue.body',
        'github.event.pull_request.title',
        'github.event.pull_request.body',
        'github.event.comment.body',
        'github.event.review.body',
        'github.event.head_commit.message',
        'github.event.head_commit.author.email',
        'github.event.head_commit.author.name',
        'github.event.pull_request.head.ref',
        'github.event.pull_request.head.label',
        'github.event.pull_request.head.repo.default_branch',
        'github.head_ref'
    ]

    # Safe refs, so that we can exclude false positives.
    SAFE_REFS = [
        'github.event.pull_request.base.sha'
    ]

    GITHUB_HOSTED_LABELS = [
        'ubuntu-latest',
        'macos-latest',
        'macOS-latest',
        'windows-latest',
        'ubuntu-18.04', # deprecated, but we don't want false positives on older repos.
        'ubuntu-20.04',
        'ubuntu-22.04',
        'windows-2022',
        'windows-2019',
        'windows-2016', # deprecated, but we don't want false positives on older repos.
        'macOS-13',
        'macOS-12',
        'macOS-11',
        'macos-11',
        'macos-12',
        'macos-13',
        'macos-13-xl',
        'macos-12',
    ]

    LARGER_RUNNER_REGEX_LIST = r'(windows|ubuntu)-(22.04|20.04|2019-2022)-(4|8|16|32|64)core-(16|32|64|128|256)gb'
    MATRIX_KEY_EXTRACTION_REGEX = r'{{\s*matrix\.([\w-]+)\s*}}'

    def __init__(self, workflow_yml: str, repo_name: str, workflow_name: str):
        """Initialize class with workflow file.

        Args:
            workflow_yml (str): String containing yaml file read in from
            repository.
            repo_name (str): Name of the repository.
            workflow_name (str): name of the workflow file
        """
        self.parsed_yml = yaml.safe_load(workflow_yml.replace('\t','  '))
        self.raw_yaml = workflow_yml
        self.repo_name = repo_name
        self.wf_name = workflow_name

    def output(self, dirpath: str):
        """Write this yaml file out to the provided directory.

        Args:
            dirpath (str): Directory to save the yaml file to.

        Returns:
            bool: Whether the file was successfully written.
        """
        Path(os.path.join(dirpath, f'{self.repo_name}')).mkdir(
            parents=True, exist_ok=True)

        with open(os.path.join(
                dirpath, f'{self.repo_name}/{self.wf_name}'), 'w') as wf_out:
            wf_out.write(self.raw_yaml)
            return True
        
    def extract_composite_actions(self):
        """
        Extracts composite actions from the workflow file.
        """
        composite_actions = []
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers:
            return []

        if 'jobs' not in self.parsed_yml:
            return composite_actions
        
        for _, job_details in self.parsed_yml['jobs'].items():
            for step in job_details.get('steps', []):
                if 'uses' in step and step['uses']:
                    action_parts = {
                        "key": step['uses'],
                        "path": step['uses'].split('@')[0] if '@' in step['uses'] else step['uses'],
                        "ref": step['uses'].split('@')[1] if '@' in step['uses'] else '',
                        "local": step['uses'].startswith('./'),
                        "args": step.get('with', {})
                    }
                    
                    # Don't investigate GitHub maintained actions
                    if not action_parts['path'].startswith('actions/'):
                        composite_actions.append(action_parts)
                            
        return composite_actions

    def extract_step_contents(self):
        """Extract the contents of 'run' steps and steps that use actions/github-script.

        Returns:
            dict: A dictionary containing the job names as keys and another dictionary as values.
                  The inner dictionary contains two keys: 'check_steps' and 'if_check'.
                  'check_steps' maps to a list of dictionaries where each dictionary contains the step name, its contents, and its 'if' check.
                  'if_check' maps to the 'if' check of the job, if it exists.
        """
        jobs_contents = {}

        if 'jobs' not in self.parsed_yml:
            return jobs_contents

        for job_name, job_details in self.parsed_yml['jobs'].items():
            job_content = {
                "check_steps": [],
                "if_check": job_details.get('if', '')
            }

            processed_steps = process_steps(job_details.get('steps', []))
            if processed_steps:
                job_content["check_steps"] = processed_steps

            jobs_contents[job_name] = job_content
        return jobs_contents

    def get_vulnerable_triggers(self):
        """Analyze if the workflow is set to execute on potentially risky triggers.

        Returns:
            list: List of triggers within the workflow that could be vulnerable
            to GitHub Actions script injection vulnerabilities.
        """
        vulnerable_triggers = []
        risky_triggers = ['pull_request_target', 'workflow_run', 'issue_comment', 'pull_request_review', 'pull_request_review_comment', 'issues']
        if not self.parsed_yml or 'on' not in self.parsed_yml:
            return vulnerable_triggers

        triggers = self.parsed_yml['on']
        if isinstance(triggers, list):
            for trigger in triggers:
                if trigger in risky_triggers:
                    vulnerable_triggers.append(trigger)
        elif isinstance(triggers, dict):
            for trigger, trigger_conditions in triggers.items():
                if trigger in risky_triggers:
                    if trigger_conditions and 'types' in trigger_conditions:
                        # If the trigger is only for labeled events, we can ignore it,
                        # but if there are other triggers there is the SE possibility.
                        if 'labeled' in trigger_conditions['types'] and len(trigger_conditions['types']) == 1:
                            continue
                        vulnerable_triggers.append(trigger)
                    else:
                        vulnerable_triggers.append(trigger)

        return vulnerable_triggers

    def analyze_checkouts(self):
        """Analyze if any steps within the workflow utilize the 'actions/checkout' action with a 'ref' parameter.

        Returns:
        list: List of 'ref' values within the 'actions/checkout' steps.
        """
        ref_values = []
        if 'jobs' not in self.parsed_yml:
            return ref_values

        for job_name, job_details in self.parsed_yml['jobs'].items():
            for step in job_details.get('steps', []):
                # Check more more than just actions/checkout in case there are alternatives
                # in use.
                if 'uses' in step and step['uses'] and '/checkout' in step['uses'] \
                        and 'with' in step and 'ref' in step['with']:
                    ref_values.append(step['with']['ref'])

        return ref_values

    def check_pwn_request(self):
        """Check for potential script injection vulnerabilities.

        Returns:
            dict: A dictionary containing the job names as keys and a list of potentially vulnerable tokens as values.
        """
        vulnerable_triggers = self.get_vulnerable_triggers()

        if not vulnerable_triggers:
            return {}

        checkout_refs = self.analyze_checkouts()

        if checkout_refs:
            cleaned_refs = list(set([ref for ref in checkout_refs if self.check_pr_ref(ref)]))
            if cleaned_refs:
                return 'Refs: ' + ' '.join(cleaned_refs)
            else:
                return {}

    @classmethod
    def check_pr_ref(cls, item):
        """
        Checks if the given item contains any of the predefined pull request related values.

        This method is used to identify if a given item (typically a string) contains any of the values defined in 
        PR_ISH_VALUES. These values are typically used to reference pull request related data in a GitHub Actions workflow.

        Args:
            item (str): The item to check.

        Returns:
            bool: True if the item contains any of the pull request related values, False otherwise.
        """
        PR_ISH_VALUES = [
            "head",
            "pr",
            "pull"
        ]

        for prefix in PR_ISH_VALUES:
            
            if prefix in item.lower():
                return True
        return False


    def check_injection(self):
        """Check for potential script injection vulnerabilities.

        Returns:
            dict: A dictionary containing the job names as keys and a list of potentially vulnerable tokens as values.
        """
        vulnerable_triggers = self.get_vulnerable_triggers()
        if not vulnerable_triggers:
            return {}

        jobs_contents = self.extract_step_contents()

        injection_risk = {}

        context_expression_regex = r'\$\{\{ ([A-Za-z0-9]+\.[A-Za-z0-9]+.*?) \}\}'

        for job_name, job_content in jobs_contents.items():
            steps_risk = {}
            for step in job_content['check_steps']: 
                if step['contents']:
                    tokens = re.findall(context_expression_regex, step['contents'])
                else:
                    continue
                # First we get known unsafe
                tokens_knownbad = [item for item in tokens if item.lower() in self.UNSAFE_CONTEXTS]
                # And then we add anything referenced 
                tokens_sus = [item for item in tokens if check_sus(item)]
                tokens = tokens_knownbad + tokens_sus
                if tokens:
                    steps_risk[step['step_name']] = {
                        "variables": list(set(tokens))             
                    }
                    if step.get('if_check', []):
                        steps_risk[step['step_name']]['if_checks'] = step['if_check']

            if steps_risk:
                injection_risk['triggers'] = vulnerable_triggers 
                injection_risk[job_name] = steps_risk
                if 'if_check' in job_content and job_content['if_check']:
                    injection_risk[job_name]['if_check'] = job_content['if_check']

        return injection_risk

    def self_hosted(self):
        """Analyze if any jobs within the workflow utilize self-hosted runners.

        Returns:
           list: List of jobs within the workflow that utilize self-hosted
           runners.
        """
        sh_jobs = []
        if not self.parsed_yml or 'jobs' not in self.parsed_yml:
            return sh_jobs

        for jobname, job_details in self.parsed_yml['jobs'].items():
            if 'runs-on' in job_details:
                runs_on = job_details['runs-on']
                # Clear cut
                if 'self-hosted' in runs_on:
                    sh_jobs.append((jobname, job_details))
                elif 'matrix.' in runs_on:
                    # We need to check each OS in the matrix strategy.
                    # Extract the matrix key from the variable
                    matrix_match = re.search(self.MATRIX_KEY_EXTRACTION_REGEX, runs_on)

                    if matrix_match:
                        matrix_key = matrix_match.group(1)
                    else:
                        continue
                    # Check if strategy exists in the yaml file
                    if 'strategy' in job_details and 'matrix' in job_details['strategy']:
                        matrix = job_details['strategy']['matrix']

                        # Use previously acquired key to retrieve list of OSes
                        if matrix_key in matrix:
                            os_list = matrix[matrix_key]
                        elif 'include' in matrix:
                            inclusions = matrix['include']
                            os_list = []
                            for inclusion in inclusions:
                                if matrix_key in inclusion:
                                    os_list.append(inclusion[matrix_key])
                        else:
                            continue

                        # We only need ONE to be self hosted, others can be
                        # GitHub hosted
                        for key in os_list:
                            if type(key) == str:
                                if key not in self.GITHUB_HOSTED_LABELS and not re.match(self.LARGER_RUNNER_REGEX_LIST, key):
                                    sh_jobs.append((jobname, job_details))
                                    break
                    pass
                else:
                    if type(runs_on) == list:
                        for label in runs_on:
                            if label in self.GITHUB_HOSTED_LABELS:
                                break
                            if re.match(self.LARGER_RUNNER_REGEX_LIST, label):
                                break
                        else:
                            sh_jobs.append((jobname, job_details))
                    elif type(runs_on) == str:
                        if runs_on in self.GITHUB_HOSTED_LABELS:
                            break
                        if re.match(self.LARGER_RUNNER_REGEX_LIST, runs_on):
                            break
                        sh_jobs.append((jobname, job_details))

        return sh_jobs
