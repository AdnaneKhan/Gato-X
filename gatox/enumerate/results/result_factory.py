# THis class encapsulates the logic for a result factory.
# it takes a Graph traversal path and worlks from start to end in order
# to populate the result.
from gatox.enumerate.results.issue_type import IssueType
from gatox.enumerate.results.pwn_request_result import PwnRequestResult
from gatox.enumerate.results.injection_result import InjectionResult
from gatox.enumerate.results.dispatch_toctou_result import DispatchTOCTOUResult

class ResultFactory():

    @staticmethod
    def create_pwn_result(path: list, confidence_score, attack_complexity):
        # Add logic for additional processing, augmentation.

        return PwnRequestResult(path, confidence_score, attack_complexity)

    @staticmethod
    def create_injection_result(path: list, confidence_score, attack_complexity):
        # Add logic for additional processing, augmentation.

        return InjectionResult(path, confidence_score, attack_complexity)

    @staticmethod
    def create_toctou_result(path: list, confidence_score, attack_complexity):
        # Add logic for additional processing, augmentation.

        return DispatchTOCTOUResult(path, confidence_score, attack_complexity)

    