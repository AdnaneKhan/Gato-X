import re

# Define classes for each type of expression
class Literal:
    def __init__(self, value):
        self.value = value

class Identifier:
    def __init__(self, name):
        self.name = name

        if self.name in ['contains', 'startsWith', 'endsWith', 'fromJson', 'toJson']:
            self.is_function = True
        self.is_function = False

class BinaryExpression:
    def __init__(self, operator, left, right):
        self.operator = operator
        self.left = left
        self.right = right

class UnaryExpression:
    def __init__(self, operator, argument):
        self.operator = operator
        self.argument = argument

class CallExpression:
    def __init__(self, callee, arguments):
        self.callee = callee
        self.arguments = arguments

# Define a tokenizer
def tokenize(input):
    # Replace ${{ and }} with ( and ), and newlines to avoid conflicts with the parser
    input = input.replace("${{" , "(").replace("}}", ")").replace("\n", " ")
    #tokens = re.findall(r"!|\(|\)|\|\||&&|!=|==|'.*?'|[a-zA-Z]+\([\w\s*'\",-_]+\)|[\w\.]+", input)
    tokens = re.findall(r"!|\(|\)|\|\||&&|!=|==|'.*?'|[\w\.]+", input)
    return tokens
class Parser:
    def __init__(self, tokens):
        """
        Initialize the Parser with a list of tokens.
        """
        self.tokens = tokens
        self.current = 0

    def parse(self):
        """
        Parse the tokens into an expression tree.
        """
        return self.expression()

    def match(self, *types):
        """
        Check if the current token matches any of the given types. If it does, consume the token and return True.
        """
        if self.check(*types):
            self.current += 1
            return True
        return False

    def check(self, *types):
        """
        Check if the current token matches any of the given types, without consuming the token.
        """
        if self.is_at_end():
            return False
        return self.peek() in types

    def peek(self):
        """
        Return the current token without consuming it.
        """
        return self.tokens[self.current]

    def is_at_end(self):
        """
        Check if all tokens have been consumed.
        """
        return self.current >= len(self.tokens)

    def expression(self):
        """
        Parse an expression.
        """
        return self.logical_or()

    def logical_or(self):
        """
        Parse a logical OR expression.
        """
        expr = self.logical_and()

        while self.match('||'):
            operator = '||'
            right = self.logical_and()
            expr = BinaryExpression(operator, expr, right)

        return expr

    def logical_and(self):
        """
        Parse a logical AND expression.
        """
        expr = self.equality()

        while self.match('&&'):
            operator = '&&'
            right = self.primary()
            expr = BinaryExpression(operator, expr, right)

        return expr

    def unary(self):
        """
        Parse a unary expression.
        """
        if self.match('!'):
            operator = '!'
            right = self.primary()
            return UnaryExpression(operator, right)
        return self.primary()

    def equality(self):
        """
        Parse an equality or inequality expression.
        """
        expr = self.call()

        while self.match('==', '!='):
            operator = self.tokens[self.current - 1]
            right = self.call()
            expr = BinaryExpression(operator, expr, right)

        return expr

    def call(self):
        """
        Parse a function call expression.
        """
        expr = self.unary()

        if self.match('('):
            arguments = []
            if not self.check(')'):
                arguments.append(self.expression())
                while self.match(','):
                    arguments.append(self.expression())
            self.match(')')
            expr = CallExpression(expr, arguments)

        return expr
    
    def primary(self):
        """
        Parse a primary expression.
        """
        if self.match('!'):
            return self.unary()

        if self.match('('):
            expr = self.expression()
            self.match(')')
            return expr

        if re.match(r"'[^']*'", self.peek()):
            value = self.peek()[1:-1]
            self.current += 1
            return Literal(value)

        if re.match(r"\w+\.\w+(?:\.\w+)*|\w+", self.peek()):
            name = self.peek()
            self.current += 1
            return Identifier(name)

        raise Exception('Unexpected token: ' + self.peek())