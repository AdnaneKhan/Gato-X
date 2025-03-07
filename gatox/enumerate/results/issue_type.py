"""
Copyright 2025, Adnan Khan

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

from enum import Enum


class IssueType(str, Enum):
    """

    Values:
        PWN_REQUEST:
        DISPATCH_TOCTOU:
        ACTIONS_INJECTION:
        ENVIRONMENT_POLLUTION:
    """

    PWN_REQUEST: str = "PwnRequestResult"
    DISPATCH_TOCTOU: str = "DispatchTOCTOUResult"
    ACTIONS_INJECTION: str = "InjectionResult"
    PR_REVIEW_INJECTON: str = "ReviewInjectionResult"
    ENVIRONMENT_POLLUTION: str = "EnvironmentPollutionResult"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)
