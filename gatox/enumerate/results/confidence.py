from enum import Enum


class Confidence(str, Enum):
    """
    Represents the confidence level in a finding or result.

    Values:
        HIGH: Strong evidence and high certainty
        MEDIUM: Moderate evidence with some uncertainty
        LOW: Limited evidence with significant uncertainty
        UNKNOWN: Not enough information to determine confidence
    """

    HIGH: str = "High"
    MEDIUM: str = "Medium"
    LOW: str = "Low"
    UNKNOWN: str = "Unknown"

    def __str__(self) -> str:
        return str(self.value)

    def __repr__(self) -> str:
        return str(self.value)

    def to_machine(self):
        """Convert enum to machine readable format for JSON serialization."""
        return self.value

    @classmethod
    def from_string(cls, value: str):
        """Convert string to enum value, case-insensitive."""
        try:
            return cls[value.upper()]
        except KeyError:
            return cls.UNKNOWN
