import json


from gatox.enumerate.results.confidence import Confidence
from gatox.enumerate.results.complexity import Complexity
from gatox.enumerate.results.analysis_result import AnalysisResult

class PwnRequestResult(AnalysisResult):
    """
    Represents the result of a Pwn request analysis.
    Inherits from AnalysisResult to include repository name, issue type,
    confidence score, and attack complexity score.
    """

    def __init__(self, path, confidence_score: Confidence, attack_complexity_score: Complexity):

        repository_name = path[0].repo_name()

        super().__init__(repository_name, PwnRequestResult.__name__, confidence_score, attack_complexity_score)

        self.__attack_path = path

    def to_machine(self):

        result = {
            "repository_name": self.repo_name(),
            "issue_type": self.issue_type(),
            "triggers": self.__attack_path[0].get_triggers(),
            "initial_workflow": self.__attack_path[0].get_workflow_name(),
            "confidence": self.confidence_score(),
            "attack_complexity": self.attack_complexity(),          
            "path": [
                str(node) for node in self.__attack_path
            ],
            "sink": self.__attack_path[-1].get_step_data() if self.confidence_score() == Confidence.HIGH else "Not Detected"
        }

        return result

    def print_human(self):
        """
        Converts the analysis result to a JSON string.

        Returns:
            str: The JSON representation of the analysis result.
        """
        
        first_node = self.__attack_path[0]
        last_node = self.__attack_path[-1]

        for j, node in enumerate( self.__attack_path, start=1):
            if "WorkflowNode" in str(node):
                print(f"    Workflow -> {node}")
            elif "JobNode" in str(node):
                print(f"      Job -> {node}")
            elif "StepNode" in str(node):
                print(f"        Step -> {node}")
                if j == len( self.__attack_path):
                    print(f"       Contents: \n{node.get_step_data()}")
            elif "ActionNode" in str(node):
                print(f"        Step -> {node}")
            else:
                print(f"    Unknown -> {node}")
        