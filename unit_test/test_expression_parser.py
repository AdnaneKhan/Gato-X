from gatox.workflow_parser.expression_parser import ExpressionParser
from gatox.workflow_parser.expression_evaluator import ExpressionEvaluator

def test_parse1():
    if_check1 = "(((github.event.action == 'labeled' && (github.event.label.name == 'approved' || github.event.label.name == 'lgtm' || github.event.label.name == 'ok-to-test')) || (github.event.action != 'labeled' && (contains(github.event.pull_request.labels.*.name, 'ok-to-test') || contains(github.event.pull_request.labels.*.name, 'approved') || contains(github.event.pull_request.labels.*.name, 'lgtm')))) && github.repository == 'feast-dev/feast')"
    
    expr = ExpressionParser(if_check1)

    expr.print_ast()


def test_parse2():
    if_check = "github.event.issue.pull_request\n&& contains(github.event.comment.body, '[test]')\n&& contains(fromJson('[\"OWNER\", \"MEMBER\"]'), github.event.comment.author_association)\n"

    expr = ExpressionParser(if_check)
    expr.print_ast()
    variables = {
        "github.event.issue.pull_request": True,
        "github.event.comment.body": "[test] testing",
        "github.event.comment.author_association": "NONE"
    }

    evaluator = ExpressionEvaluator(variables)
    result = evaluator.evaluate(expr.get_node())

    print(f"Result of the expression '{if_check}' is: {result}")

    assert result is False

def test_simple_evaluate():
    # Example usage:
    variables = {
        "github.event.issue.pull_request": True
    }
    expression = "github.event.issue.pull_request"
    parser = ExpressionParser(expression)
    ast_root = parser.get_node()

    evaluator = ExpressionEvaluator(variables)
    result = evaluator.evaluate(ast_root)
    print(f"Result of the expression '{expression}' is: {result}")
    assert result is True
