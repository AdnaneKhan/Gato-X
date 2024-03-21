from gato.workflow_parser.expression_analyzer import Parser, tokenize, BinaryExpression, UnaryExpression, CallExpression, Identifier, Literal

def print_ast(node, indent=""):
    if isinstance(node, BinaryExpression):
        print(f"{indent}BinaryExpression:")
        print(f"{indent}  Operator: {node.operator}")
        print(f"{indent}  Left:")
        print_ast(node.left, indent + "    ")
        print(f"{indent}  Right:")
        print_ast(node.right, indent + "    ")
    elif isinstance(node, UnaryExpression):
        print(f"{indent}UnaryExpression:")
        print(f"{indent}  Operator: {node.operator}")
        print(f"{indent}  Argument:")
        print_ast(node.argument, indent + "    ")
    elif isinstance(node, CallExpression):
        print(f"{indent}CallExpression:")
        print(f"{indent}  Callee:")
        print_ast(node.callee, indent + "    ")
        print(f"{indent}  Arguments:")
        for arg in node.arguments:
            print_ast(arg, indent + "    ")
    elif isinstance(node, Identifier):
        print(f"{indent}Identifier: {node.name}")
    elif isinstance(node, Literal):
        print(f"{indent}Literal: {node.value}")
    else:
        print(type(node))
        print(f"{indent}Unknown node: {node}")

def test_tokenize():
    if_check1 = "(((github.event.action == 'labeled' && (github.event.label.name == 'approved' || github.event.label.name == 'lgtm' || github.event.label.name == 'ok-to-test')) || (github.event.action != 'labeled' && (contains(github.event.pull_request.labels.*.name, 'ok-to-test') || contains(github.event.pull_request.labels.*.name, 'approved') || contains(github.event.pull_request.labels.*.name, 'lgtm')))) && github.repository == 'feast-dev/feast')"
    
    tokens = tokenize(if_check1)

    print(tokens)

def test_contains_fromjson():
    if_check = "github.event.issue.pull_request\n&& contains(github.event.comment.body, '[test]')\n&& contains(fromJson('[\"OWNER\", \"MEMBER\"]'), github.event.comment.author_association)\n"

    tokens = tokenize(if_check)

    print(tokens)

    ast = Parser(tokens).parse()
    print_ast(ast)
    assert False