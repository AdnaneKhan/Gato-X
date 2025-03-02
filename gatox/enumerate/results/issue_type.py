from enum import Enum


class IssueType(str, Enum):
    """

    Values:
        PWN_REQUEST:
        DISPATCH_TOCTOU:
        ACTIONS_INJECTION:
        ENVIRONMENT_POLLUTION:
    """

    PWN_REQUEST: str = "Pwn Request"
    DISPATCH_TOCTOU: str = "Dispatch Time-of-Check to Time-of-Use"
    ACTIONS_INJECTION: str = "Actions Injection"
    PR_REVIEW_INJECTON: str = "Pull Request Review Injection"
    ENVIRONMENT_POLLUTION: str = "Environment Pollution"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)
