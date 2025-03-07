"""
Copyright 2025, Adnan Khan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import re


class Node:
    def __init__(self, type, value=None, children=None):
        self.type = type
        self.value = value
        self.children = children or []


class ExpressionParser:
    def __init__(self, expression):
        self.expression = expression
        self.tokens = self.tokenize(expression)
        self.parsed_expression = self.parse_expression(self.tokens)

    def __print_ast(self, node, level=0):
        indent = "  " * level
        print(f"{indent}{node.type}: {node.value}")
        for child in node.children:
            self.__print_ast(child, level + 1)

    @staticmethod
    def tokenize(expression: str):
        token_specification = [
            ("LPAREN", r"\("),
            ("RPAREN", r"\)"),
            ("COMMA", r","),
            ("AND", r"&&"),
            ("OR", r"\|\|"),
            ("EQUALS", r"=="),
            ("NOT_EQUALS", r"!="),
            ("NEGATION", r"!"),  # Unary negation
            ("IDENTIFIER", r"[a-zA-Z_.][a-zA-Z0-9-_.*]*"),
            ("STRING", r"'[^']*'"),
            ("WHITESPACE", r"\s+"),
        ]
        tok_regex = "|".join(
            f"(?P<{name}>{pattern})" for name, pattern in token_specification
        )
        return [
            (match.lastgroup, match.group(0))
            for match in re.finditer(tok_regex, expression)
            if match.lastgroup != "WHITESPACE"
        ]

    @staticmethod
    def expect_token(tokens, expected_type):
        if tokens and tokens[0][0] == expected_type:
            return tokens.pop(0)
        raise SyntaxError(
            f"Expected {expected_type} but got {tokens[0] if tokens else 'no more tokens'}"
        )

    @staticmethod
    def parse_expression(tokens):
        if not tokens:
            raise SyntaxError("Empty expression")
        node = ExpressionParser.parse_logical_or(tokens)
        return node

    @staticmethod
    def parse_logical_or(tokens):
        node = ExpressionParser.parse_logical_and(tokens)
        while tokens and tokens[0][0] == "OR":
            op = tokens.pop(0)
            rhs = ExpressionParser.parse_logical_and(tokens)
            node = Node("logical_or", op[1], [node, rhs])
        return node

    @staticmethod
    def parse_logical_and(tokens):
        # Start with first comparison
        node = ExpressionParser.parse_comparison(tokens)
        # Keep chaining AND operations as long as we see &&
        while tokens and tokens[0][0] == "AND":
            op = tokens.pop(0)
            rhs = ExpressionParser.parse_comparison(tokens)
            # Create new AND node with previous node as left child
            node = Node("logical_and", op[1], [node, rhs])

        return node

    @staticmethod
    def parse_comparison(tokens):
        node = ExpressionParser.parse_unary(
            tokens
        )  # Updated from parse_primary to parse_unary
        while tokens and tokens[0][0] in ("EQUALS", "NOT_EQUALS"):
            op = tokens.pop(0)
            rhs = ExpressionParser.parse_unary(
                tokens
            )  # Updated from parse_primary to parse_unary
            node = Node("comparison", op[1], [node, rhs])
        return node

    @staticmethod
    def parse_function_call(tokens):
        function_name = ExpressionParser.expect_token(tokens, "IDENTIFIER")[1]
        ExpressionParser.expect_token(tokens, "LPAREN")
        arguments = []
        while tokens[0][0] != "RPAREN":
            arguments.append(ExpressionParser.parse_expression(tokens))
            if tokens[0][0] != "RPAREN":
                ExpressionParser.expect_token(tokens, "COMMA")
        ExpressionParser.expect_token(tokens, "RPAREN")
        return Node("function_call", function_name, arguments)

    @staticmethod
    def parse_unary(tokens):
        if tokens and tokens[0][0] == "NEGATION":
            op = tokens.pop(0)
            operand = ExpressionParser.parse_unary(
                tokens
            )  # Unary negation can be nested
            return Node("unary_negation", op[1], [operand])
        else:
            return ExpressionParser.parse_primary(tokens)

    @staticmethod
    def parse_primary(tokens):
        if tokens[0][0] == "LPAREN":
            tokens.pop(0)
            node = ExpressionParser.parse_expression(tokens)
            ExpressionParser.expect_token(tokens, "RPAREN")
            return node
        elif tokens[0][0] == "IDENTIFIER":
            # Lookahead to check if this is a function call
            if len(tokens) > 1 and tokens[1][0] == "LPAREN":
                return ExpressionParser.parse_function_call(tokens)
            else:
                return Node("identifier", tokens.pop(0)[1])
        elif tokens[0][0] == "STRING":
            return Node("string", tokens.pop(0)[1])

        elif tokens[0][0] == "AND" or tokens[0][0] == "OR":
            tokens.pop(0)
            node = ExpressionParser.parse_expression(tokens)
            return node
        else:
            raise SyntaxError(f"Unexpected token: {tokens[0][1]}")

    def print_ast(self):
        self.__print_ast(self.parsed_expression)

    def get_node(self):
        return self.parsed_expression
