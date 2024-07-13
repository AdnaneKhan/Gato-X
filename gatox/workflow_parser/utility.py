from gatox.configuration.configuration_manager import ConfigurationManager
from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

@staticmethod
def check_sus(item):
    """
    Check if the given item starts with any of the predefined suspicious prefixes.

    This method is used to identify potentially unsafe or 
    suspicious variables in a GitHub Actions workflow.
    It checks if the item starts with any of the prefixes 
    defined in PREFIX_VALUES. These prefixes are typically
    used to reference variables in a GitHub Actions workflow, 
    and if a user-controlled variable is referenced
    without proper sanitization, it could lead to a script 
    injection vulnerability.

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

    item_lower = item.lower()
    for prefix in PREFIX_VALUES:
        if item_lower.startswith(prefix):
            for safe_string in ConfigurationManager().WORKFLOW_PARSING['SAFE_ISH_CONTEXTS']:
                if item_lower.endswith(safe_string):
                    break
            else:
                return True
    return False

@staticmethod
def check_pr_ref(item):
    """
    Checks if the given item contains any of the predefined pull request 
    related values.

    This method is used to identify if a given item (typically a string) 
    contains any of the values defined in PR_ISH_VALUES. These values are 
    typically used to reference pull request related data in a GitHub Actions workflow.

    Args:
        item (str): The item to check.

    Returns:
        bool: True if the item contains any of the pull request related values, False otherwise.
    """
    for prefix in ConfigurationManager().WORKFLOW_PARSING['PR_ISH_VALUES']:
        if prefix in item.lower() and "base" not in item.lower():
            return True
    return False

@staticmethod
def filter_tokens(tokens):
    """
    This method filters the tokens from the contents of a step 
    in a GitHub workflow for potentially unsafe or suspicious context expressions.

    Parameters:
    contents (str): The contents of a step in a GitHub workflow.

    The method uses a regular expression to find all context expressions in the contents. 
    A context expression in a GitHub workflow is a string that starts with '${{' and ends with '}}'.
    The expression inside the curly braces is split by '.' into three parts. 
    The first part must be a sequence of alphanumeric characters, 
    the second part must also be a sequence of alphanumeric characters, 
    and the third part can be any sequence of characters.

    The method then checks each found context expression in two ways:
    1. Against a list of known unsafe context expressions. 
        If the context expression is found in the list, it is added to `tokens_knownbad`.
    2. Using the `check_sus` method. If `check_sus` returns 
        True for a context expression, it is added to `tokens_sus`.

    The method returns a list of tokens that are either known to be unsafe or are considered suspicious.

    Returns:
    list: A list of unsafe or suspicious context expressions found in the contents.
    """
    # First we get known unsafe
    tokens_knownbad = [
        item for item in tokens if item.lower() in \
        ConfigurationManager().WORKFLOW_PARSING['UNSAFE_CONTEXTS']
    ]
    # And then we add anything referenced 
    tokens_sus = [item for item in tokens if check_sus(item)]
    tokens_knownbad.extend(tokens_sus)
    return tokens_knownbad

@staticmethod
def check_always_true(if_check):
    """Check if the if check is always true because it uses ${{ }} in combination with
    an expression or uses nested expressions.
    """
    # If it starts with an expression but ends without, then it
    # always will resolve to true.
    if if_check.strip().startswith('${{') and not if_check.endswith('}}'):
        return True


@staticmethod
def validate_if_check(if_check, variables):
    """Function used to validate each if check.
    The strategy here is to "fail open". If we cannot
    determine with certainty the check would fail in an injection
    or pwn request scenario then we return True, because we would rather
    not miss a potential vulnerability.
    """
    if not if_check:
        return True
    
    if check_always_true(if_check):
        return True

    print(if_check)
    parser = ExpressionParser(if_check)
    ast_root = parser.get_node()

    evaluator = ExpressionEvaluator(variables)
    result = evaluator.evaluate(ast_root)

    return result