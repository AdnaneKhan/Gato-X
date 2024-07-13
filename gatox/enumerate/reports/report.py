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
from gatox.models.repository import Repository

class Report:
    """Parent class for report formatting classes.
    """

    @classmethod
    def print_header(cls, repo: Repository, report_type):
        """Prints a header for the repository report.
        """
        Output.generic(f" Repository Name: {repo.name}")
        Output.generic(f" Report Type: {report_type}")

    @classmethod
    def print_divider(cls):
        """Prints a divider with `=` symbols.
        """
        Output.generic(f'{"="*78}')
