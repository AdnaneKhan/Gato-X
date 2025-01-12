from enum import StrEnum

class IssueType(StrEnum):
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
    ENVIRONMENT_POLLUTION: str = "Environment Pollution"
