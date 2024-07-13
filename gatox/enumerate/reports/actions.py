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

from gatox.cli.output import Output
from gatox.configuration.configuration_manager import ConfigurationManager

from gatox.enumerate.reports.report import Report
from gatox.models.repository import Repository

class ActionsReport(Report):
    """
    """

    ENVIRONMENT_TOCTOU =  (
        "The workflow contains an"
        " environment protection rule"
        " but the workflow uses a mutable reference to checkout PR code."
        " This could be exploited via a race condition."
        " See https://github.com/AdnaneKhan/ActionsTOCTOU!"
    )
    LABEL_TOCTOU = ( 
        "The workflow contains "
        "label-based gating but the workflow uses a mutable reference "
        "to check out PR code. This could be exploited via a race condition. "
        "See https://github.com/AdnaneKhan/ActionsTOCTOU!"
    )
    PERMISSION_TOCTOU = (
        "The workflow contains a permission check, but uses a mutable reference"
        "to check out PR code. This could be exploited via a race condition. "
        "See https://github.com/AdnaneKhan/ActionsTOCTOU!"
    )

    PWN_REQUEST = (
        "The workflow runs on a risky trigger "
        "and might check out the PR code, see if it runs it!"
    )
    ACTIONS_INJECTION = (
        "The workflow uses variables by context expression"
        " within run or script steps. If the step is reachable and the variables are "
        "user controlled, then they can be used to inject arbitrary code into the workflow."
    )

    @classmethod
    def report_pwn(cls, repo: Repository):
        """Report Pwn Requests in the repository in a clean, human readable format.
        """
        if repo.has_pwn_request():
            risks = repo.pwn_req_risk

            first = True
            for entry in risks:    
                details = cls.__capture_pwn_details(repo, entry)

                if details and first:
                    cls.print_divider()
                    cls.print_header(repo, "Actions Pwn Requests")
         
                    first = False

                for line in details:
                    Output.generic(line)

            if first == False:
                cls.print_divider()

    @classmethod
    def report_injection(cls, repo: Repository):
        """Report injection for the repository.
        """
        if repo.has_injection():
            risks = repo.injection_risk

            first = True
            for entry in risks:
                details = cls.__capture_injection_details(repo, entry)

                if details and first:
                    cls.print_divider()
                    cls.print_header(repo, "Actions Script Injection")
                    first = False

                for line in details:
                    Output.generic(line)

            if first == False:
                cls.print_divider()

    @classmethod
    def __reusable_details(
            cls, 
            entry: dict,
            workflow_url: str,
            issue_type: str, 
            description: str, 
            triggers: list[str],
            designation
        ):
        """Reusable details printer.
        """
        details = []
        details.append(f"{'-'*78}")
        details.append(f" Workflow Name: {Output.yellow(entry['workflow_name'])}")
        details.append(f" Issue Type: {issue_type}")
        details.append(f' Trigger(s): {Output.yellow(",".join(triggers))}')
        details.append(f" Details: {description}")
        details.append(f" Workflow URL: {Output.blue(workflow_url)}")
        if 'parent_workflow' in entry:
            details.append(f" Calling Workflow: {Output.yellow(entry['parent_workflow'])}")
        details.append(f' Confidence: {Output.red(designation)}')

        return details

    @classmethod
    def __check_mutable(self, repository, entry, step):
        # If we have a sha, it's immutable so skip.
        if 'github.event.pull_request.head.sha' in step['ref'].lower():
            repository.clear_pwn_request(entry['workflow_name'])
            return False
        return True

    @classmethod
    def __report_jobs(self, candidate, details):
        """Report pwn request candidate jobs, their steps, and if-checks.
        """
        lines = []

        lines.append(f"{'~'*78}")
        lines.append(f' Job: {Output.bright(candidate)}')
            
        if details.get('if_check', ''):
            lines.append(f' Job If-Check: {details["if_check"]}')
        for step in details['steps']:
            lines.append(f' Checkout Ref: {step["ref"]}')
            if 'if_check' in step and step['if_check']:
                lines.append(f' Step If-check: {step["if_check"]}')

        return lines

    @classmethod
    def ___report_injection(self, candidate, details):
        """Create lines for each part of the injection report.
        """
        lines = []
        confidence = 'UNKNOWN'

        lines.append(f"{'~'*78}")
        lines.append(f' Job: {Output.bright(candidate)}')
        
        if details.get('if_check', ''):
            if details["if_check"].startswith('RESTRICTED'):
                confidence = "LOW"
            lines.append(f' Job If-Check: {details["if_check"]}')

        for step_name, val in details.items():
            if step_name == 'if_check':
                continue

            lines.append(f"Step: {step_name}")
            for var in val["variables"]:
                if confidence == 'UNKNOWN' and \
                    var in ConfigurationManager().WORKFLOW_PARSING['UNSAFE_CONTEXTS']:
                    confidence = "HIGH"
            lines.append(f'Variables: {", ".join(val["variables"])}')
            if 'if_checks' in val and val['if_checks']:
                lines.append(f' Step If-check: {val["if_checks"]}')

        return lines, confidence

    @classmethod
    def __capture_injection_details(cls, repository: Repository, entry: dict):
        """Print details about potential GitHub Actions script injections.
        """
        designation = "UNKNOWN"
        workflow_url = (
            entry['workflow_url']
        )

        injection = entry['details']
    
        job_reports = []
        sub_entries = []
        for k, v in injection.items():
            
            if k == 'triggers':
                continue
            else:         
                entries, confidence = cls.___report_injection(k, v)
                # Only goes up.
                if designation == 'UNKNOWN':
                    designation = confidence
                sub_entries.extend(entries)

        job_reports.extend(cls.__reusable_details(
            entry, 
            workflow_url, 
            "Actions Injection", 
            cls.ACTIONS_INJECTION, 
            injection["triggers"], 
            designation
        ))
        job_reports.extend(sub_entries)
        
        return job_reports

    @classmethod
    def __capture_pwn_details(cls, repository: Repository, entry: dict) -> list:
        """
        """
        designation = "UNKNOWN"
        pwn_req = entry['details']
        workflow_url = (
           entry['workflow_url']
        )
        job_reports = []

        if entry['environments']:
            sub_entries = []
            for candidate, details in pwn_req['candidates'].items():
                for step in details['steps']:
                    if not cls.__check_mutable(repository, entry, step):
                        return []
                    
                    if details['confidence'] and details['confidence'] in \
                        ['MEDIUM','HIGH'] and designation in ['UNKNOWN','LOW']:
                        designation = details['confidence']
                sub_entries.extend(cls.__report_jobs(candidate, details))
            job_reports.extend(cls.__reusable_details(
                entry,
                workflow_url,
                "Pwn Request with Approval TOCTOU",
                cls.ENVIRONMENT_TOCTOU,
                pwn_req["triggers"],
                designation,       
            ))
            job_reports.extend(sub_entries)
        elif len(pwn_req['triggers']) == 1 and pwn_req['triggers'][0] == 'pull_request_target:labeled':
            sub_entries = []
            for candidate, details in pwn_req['candidates'].items():
                for step in details['steps']:
                    if not cls.__check_mutable(repository, entry, step):
                        return []
                    
                if details['confidence'] and details['confidence'] in \
                    ['MEDIUM','HIGH'] and designation in ['UNKNOWN','LOW']:
                    designation = details['confidence']

                sub_entries.extend(cls.__report_jobs(candidate, details))
            job_reports.extend(cls.__reusable_details(
                entry,
                workflow_url,
                "Pwn Request with Label TOCTOU",
                cls.LABEL_TOCTOU,
                pwn_req["triggers"],
                designation
            ))
            job_reports.extend(sub_entries)
        else:
            toctou = False
            
            sub_entries = []
            for candidate, details in pwn_req['candidates'].items():
                if details['gated']:
                    for step in details['steps']:
                        if not cls.__check_mutable(repository, entry, step) and \
                            (not ("issue_comment" in pwn_req["triggers"] and len(pwn_req["triggers"]) == 1)):     
                            return []
                        else:
                            toctou = True

                if details['confidence'] and details['confidence'] in \
                        ['MEDIUM','HIGH'] and designation in ['UNKNOWN','LOW']:
                        designation = details['confidence']
                sub_entries.extend(cls.__report_jobs(candidate, details))

            if toctou:
                # If we got here then it is at least medium.
                if designation == 'UNKNOWN':
                    designation = 'MEDIUM'
                job_reports.extend(cls.__reusable_details(
                    entry,
                    workflow_url,
                    "Pwn Request With Permission TOCTOU",
                    cls.PERMISSION_TOCTOU,
                    pwn_req["triggers"],
                    designation
                ))
                job_reports.extend(sub_entries)
            else:
                job_reports.extend(cls.__reusable_details(
                    entry,
                    workflow_url,
                    "Pwn Request",
                    cls.PWN_REQUEST,
                    pwn_req["triggers"],
                    designation
                ))
                job_reports.extend(sub_entries)
        return job_reports