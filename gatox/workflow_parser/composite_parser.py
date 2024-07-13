import yaml

from yaml import CSafeLoader

class CompositeParser():
    """
    A class to parse and analyze GitHub Actions workflows.

    Attributes:
        UNSAFE_CONTEXTS (list): A list of context expressions that are considered unsafe.
        parsed_yml (dict): The parsed YAML file.
    """

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

    def __init__(self, action_yml: str):
        """
        Initializes the CompositeParser instance by loading and parsing the provided YAML file.

        Args:
            action_yml (str): The YAML file to parse.
        """
        self.parsed_yml = yaml.load(action_yml.replace('\t','  ') ,Loader=CSafeLoader)

    @staticmethod
    def check_sus(item):
        """
        Checks if the given item starts with any of the predefined suspicious prefixes.

        Args:
            item (str): The item to check.

        Returns:
            bool: True if the item starts with any of the suspicious prefixes, 
            False otherwise.
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
        Checks if the parsed YAML file represents a composite GitHub Actions workflow.

        Returns:
            bool: True if the parsed YAML file represents a composite GitHub 
            Actions workflow, False otherwise.
        """
        if 'runs' in self.parsed_yml and 'using' in self.parsed_yml['runs']:
            return self.parsed_yml['runs']['using'] == 'composite'
        
    # def check_injection(self, inbound_variables=None):
    #     """
    #     Checks if the composite action contains any unsafe context expressions.

    #     Args:
    #         inbound_variables (list, optional): A list of inbound variables to 
    #         check for unsafe context expressions. Defaults to None.

    #     Returns:
    #         list: A list of steps that contain unsafe context expressions.
    #     """
    #     if not self.is_composite():
    #         return False

    #     context_expression_regex = r'\$\{\{ ([A-Za-z0-9]+\.[A-Za-z0-9]+.*?) \}\}'
    #     step_risk = []

    #     steps = self.parsed_yml['runs'].get('steps', [])
    #     processed_steps = process_steps(steps)
    #     for step in processed_steps:
            
    #         if step['contents']:
    #             tokens = re.findall(context_expression_regex, step['contents'])
    #         else:
    #             continue
    #         # First we get known unsafe
    #         tokens_knownbad = [item for item in tokens if item.lower() in self.UNSAFE_CONTEXTS]
    #         # And then we add anything referenced 
    #         tokens_sus = [item for item in tokens if self.check_sus(item)]
    #         tokens = tokens_knownbad + tokens_sus
    #         if tokens:
    #             step_risk.append({step['step_name']: tokens})

    #     return step_risk