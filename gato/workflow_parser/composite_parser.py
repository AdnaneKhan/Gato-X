import yaml
import re

from gato.workflow_parser.utility import process_steps

class CompositeParser():


    UNSAFE_CONTEXTS = [
        'github.event.issue.title',
        'github.event.issue.body',
        'github.event.pull_request.title',
        'github.event.pull_request.body',
        'github.event.comment.body',
        'github.event.review.body',
        'github.event.head_commit.message',
        'github.event.head_commit.author.email',
        'github.event.head_commit.author.name',
        'github.event.pull_request.head.ref',
        'github.event.pull_request.head.label',
        'github.event.pull_request.head.repo.default_branch',
        'github.head_ref'
    ]

    """
    """
    def __init__(self, action_yml: str):
        self.parsed_yml = yaml.safe_load(action_yml.replace('\t','  '))

    @staticmethod
    def check_sus(item):
        """
        Check if the given item starts with any of the predefined suspicious prefixes.

        This method is used to identify potentially unsafe or suspicious variables in a GitHub Actions workflow.
        It checks if the item starts with any of the prefixes defined in PREFIX_VALUES. These prefixes are typically
        used to reference variables in a GitHub Actions workflow, and if a user-controlled variable is referenced
        without proper sanitization, it could lead to a script injection vulnerability.

        Args:
            item (str): The item to check.

        Returns:
            bool: True if the item starts with any of the suspicious prefixes, False otherwise.
        """

        PREFIX_VALUES = [
            "needs.",
            "env.",
            "steps.",
            "inputs."
        ]

        for prefix in PREFIX_VALUES:
            if item.lower().startswith(prefix):
                return True
        return False

    
    def is_composite(self):
        """
        """
        if 'runs' in self.parsed_yml and 'using' in self.parsed_yml['runs']:
            return self.parsed_yml['runs']['using'] == 'composite'
        
    def check_injection(self, inbound_variables=None):
        """Checks if the composite action contains any unsafe context expressions.
        """

        if not self.is_composite():
            return False

        context_expression_regex = r'\$\{\{ ([A-Za-z0-9]+\.[A-Za-z0-9]+.*?) \}\}'
        step_risk = []

        steps = self.parsed_yml['runs'].get('steps', [])
        processed_steps = process_steps(steps)

        for step in processed_steps:
            if step['contents']:
                tokens = re.findall(context_expression_regex, step['contents'])
            else:
                continue
            # First we get known unsafe
            tokens_knownbad = [item for item in tokens if item.lower() in self.UNSAFE_CONTEXTS]
            # And then we add anything referenced 
            tokens_sus = [item for item in tokens if self.check_sus(item)]
            tokens = tokens_knownbad + tokens_sus
            if tokens:
                step_risk.append({step['step_name']: tokens})

        return step_risk