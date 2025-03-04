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


class Complexity(str, Enum):
    """
    Represents the complexity level of a workflow vulnerability.

    Values:
        ZERO_CLICK: Exploit requires no user interaction
        TOCTOU: Time-of-check to time-of-use vulnerability
        BROKEN_ACCESS: Broken access control vulnerability
        DEFAULT_DEPENDENT: Vulnerability depends on default configuration
    """

    ZERO_CLICK = "Zero Click"
    FOLLOW_UP = "Persistent Approval Gated"
    TOCTOU = "Time-of-Check to Time-of-Use"
    BROKEN_ACCESS = "Broken Access Control"
    DEFAULT_DEPENDENT = "Default Configuration Dependent"
    CONTRIBUTION_REQUIRED = "Workflow Run Triggered Issue"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)
