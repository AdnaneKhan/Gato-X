import yaml

from gatox.attack.pwnrequest.steps.pull_request import PullRequest
from gatox.attack.pwnrequest.steps.catcher import Catcher
from gatox.attack.pwnrequest.steps.comment import CommentStep
from gatox.attack.pwnrequest.steps.dispatch import DispatchStep


class StepFactory:

    @staticmethod
    def create_steps(target: str, attack_template: dict):
        """Create a list of steps from the attack template."""
        steps = []

        gist_pat = attack_template.get("gist_pat", None)

        if not gist_pat:
            raise ValueError("Gist PAT is required for the attack.")

        for step_definition in attack_template["steps"]:
            if step_definition["type"] == "PullRequest":
                step = PullRequest(
                    target,
                    step_definition["base_branch"],
                    step_definition["head_branch"],
                    step_definition["target_workflow"],
                    gist_pat,
                    modified_files=step_definition.get("modified_files", []),
                )

                steps.append(step)
            elif step_definition["type"] == "Catcher":
                expected_secrets = step_definition["expected_secrets"]
                step = Catcher(expected_secrets, gist_pat)

                steps.append(step)
            elif step_definition["type"] == "Comment":
                step = CommentStep(step_definition["comment"])

                steps.append(step)
            elif step_definition["type"] == "Dispatch":
                step = DispatchStep(
                    step_definition["workflow"],
                    step_definition["inputs"],
                    target_branch=step_definition.get("target_branch", None),
                )

                steps.append(step)

        return steps
