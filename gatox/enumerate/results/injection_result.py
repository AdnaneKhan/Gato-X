import json


from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.analysis_result import AnalysisResult


class InjectionResult(AnalysisResult):
    """
    Represents the result of an Injection analysis.
    Inherits from AnalysisResult to include repository name, issue type,
    confidence score, and attack complexity score.
    """

    def __init__(
        self,
        path: list,
        confidence_score: Confidence,
        attack_complexity_score: Complexity,
    ):

        repository_name = path[0].repo_name()

        super().__init__(
            repository_name,
            InjectionResult.__name__,
            confidence_score,
            attack_complexity_score,
        )

        self.__attack_path = path

    def to_machine(self):

        result = {
            "repository_name": self.repo_name(),
            "issue_type": self.issue_type(),
            "triggers": self.__attack_path[0].get_triggers(),
            "initial_workflow": self.__attack_path[0].get_workflow_name(),
            "confidence": self.confidence_score(),
            "attack_complexity": self.attack_complexity(),
            "path": [node for node in self.collect_steps(self.__attack_path)],
            "injectable_context": self.__attack_path[-1].contexts,
        }

        return result
