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
