from enum import StrEnum

class Complexity(StrEnum):
    """
    Represents the complexity level of a workflow vulnerability.

    Values:
        ZERO_CLICK: Exploit requires no user interaction
        TOCTOU: Time-of-check to time-of-use vulnerability
        BROKEN_ACCESS: Broken access control vulnerability  
        DEFAULT_DEPENDENT: Vulnerability depends on default configuration
    """
    
    ZERO_CLICK = "Zero Click"
    TOCTOU = "Time-of-Check to Time-of-Use"
    BROKEN_ACCESS = "Broken Access Control"
    DEFAULT_DEPENDENT = "Default Configuration Dependent"
