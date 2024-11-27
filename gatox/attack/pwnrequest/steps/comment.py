from gatox.attack.pwnrequest.steps.attack_step import AttackStep


class CommentStep(AttackStep):
    """Step representing a specific issue comment to make on an issue or a pull request."""

    def __init__(self, comment: str):
        self.comment = comment

    def handoff(self):
        """ """
        pass
