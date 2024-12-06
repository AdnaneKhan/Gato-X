from gatox.attack.attack import Attacker
from gatox.cli.output import Output

from gatox.attack.pwnrequest.step_factory import StepFactory


class PwnRequest(Attacker):
    """PwnRequest attack module.

    This module is responsible for performing a PwnRequest attack on a target
    repository. It is driven by an attack template file which specifies the
    actions.

    It handles injections too.
    """

    def execute_attack(self, target_repo: str, attack_template: dict):
        """Executes attack based on the template provided."""
        self.setup_user_info()

        Output.info("Preparing Gato-X Pwn Request Attack!")

        Output.warn(
            "The Gist PAT will be briefly exposed, please make sure to use a fine grained PAT with only gists:write permission."
        )

        steps = StepFactory.create_steps(target_repo, attack_template)
        results = {}

        Output.info("Setting up attack, please follow the prompts.")
        for step in steps:
            status = step.setup(self.api)
            if not status:
                Output.error(f"Failed to setup step: {step}, aborting.")
                return False

        Output.info("All setup complete, starting attack.")
        for step in steps:
            Output.info(f"Executing step: {step.step_data}")

            status = step.preflight(self.api, **results)
            if not status:
                Output.error(f"Failed perform preflight for step: {step}")
                return False

            status = step.execute(self.api)
            if not status:
                Output.error(f"Failed to execute step: {step}")
                return False

            results = step.handoff()
