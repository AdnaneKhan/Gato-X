import re


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
        "jobs."
    ]

    for prefix in PREFIX_VALUES:
        if item.lower().startswith(prefix):
            return True
    return False

@staticmethod
def process_steps(steps):
    """
    """

    step_details = []
    for step in steps:
        step_name = step.get('name', 'NAME_NOT_SET')
        step_if_check = step.get('if', '')
        if 'run' in step:
            step_details.append({"contents": step['run'], "if_check": step_if_check, "step_name": step_name})
        elif step.get('uses', '') == 'actions/github-script' and 'with' in step and 'script' in step['with']:
            step_details.append({"contents": step['with']['script'], "if_check": step_if_check, "step_name": step_name})

    return step_details

@staticmethod
def check_contents(contents):
    """
    """
    context_expression_regex = r'\$\{\{ ([A-Za-z0-9]+\.[A-Za-z0-9]+\..*?) \}\}'
    tokens = re.findall(context_expression_regex, contents)

    # First we get known unsafe
    tokens_knownbad = [item for item in tokens if item.lower() in UNSAFE_CONTEXTS]
    # And then we add anything referenced 
    tokens_sus = [item for item in tokens if check_sus(item)]
    tokens = tokens_knownbad + tokens_sus