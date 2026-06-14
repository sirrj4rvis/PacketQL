"""Recursive-descent parser → SelectNode AST.

Grammar (precedence falls out of the rule layering):

    select     ::= SELECT select_list FROM ident [WHERE expr]
                   [ORDER BY ident [ASC|DESC]] [LIMIT integer]
    expr       ::= or_expr
    or_expr    ::= and_expr {OR and_expr}
    and_expr   ::= not_expr {AND not_expr}
    not_expr   ::= NOT not_expr | comparison
    comparison ::= primary [ (op | LIKE) primary ]
    primary    ::= "(" expr ")" | integer | float | string | ident

An IP-string literal compared to an IP column (``src_ip = '192.168.1.1'``) is
converted to its uint32 form here, before planning — IPs are integers downstream.
"""

from __future__ import annotations

from packetql.query import ast
from packetql.query.lexer import SQLSyntaxError, TokenType, tokenize
from packetql.schema import ip_to_int

IP_COLUMNS = {"src_ip", "dst_ip"}
_COMPARISONS = {"=", "!=", "<", ">", "<=", ">="}


class Parser:
    def __init__(self, tokens) -> None:
        self._toks = tokens
        self._i = 0

    def _peek(self):
        return self._toks[self._i]

    def _next(self):
        tok = self._toks[self._i]
        self._i += 1
        return tok

    def _is_kw(self, kw: str) -> bool:
        t = self._peek()
        return t.type == TokenType.KEYWORD and t.lexeme == kw

    def _expect_kw(self, kw: str):
        if not self._is_kw(kw):
            raise SQLSyntaxError(f"expected {kw}, got {self._peek().lexeme!r}")
        return self._next()

    def _expect(self, tt: TokenType):
        t = self._peek()
        if t.type != tt:
            raise SQLSyntaxError(f"expected {tt.name}, got {t.type.name} {t.lexeme!r}")
        return self._next()

    def parse(self) -> ast.SelectNode:
        self._expect_kw("SELECT")
        columns = self._select_list()
        self._expect_kw("FROM")
        table = self._expect(TokenType.IDENTIFIER).lexeme
        where = self._expr() if self._consume_kw("WHERE") else None
        order_by = None
        if self._consume_kw("ORDER"):
            self._expect_kw("BY")
            col = self._expect(TokenType.IDENTIFIER).lexeme
            descending = False
            if self._consume_kw("ASC"):
                descending = False
            elif self._consume_kw("DESC"):
                descending = True
            order_by = ast.OrderBy(col, descending)
        limit = self._expect(TokenType.INTEGER).value if self._consume_kw("LIMIT") else None
        self._expect(TokenType.EOF)
        return ast.SelectNode(columns, table, where, order_by, limit)

    def _consume_kw(self, kw: str) -> bool:
        if self._is_kw(kw):
            self._next()
            return True
        return False

    def _select_list(self):
        if self._peek().type == TokenType.STAR:
            self._next()
            return ["*"]
        cols = [self._expect(TokenType.IDENTIFIER).lexeme]
        while self._peek().type == TokenType.COMMA:
            self._next()
            cols.append(self._expect(TokenType.IDENTIFIER).lexeme)
        return cols

    def _expr(self):
        return self._or_expr()

    def _or_expr(self):
        node = self._and_expr()
        while self._consume_kw("OR"):
            node = ast.BinaryOp("OR", node, self._and_expr())
        return node

    def _and_expr(self):
        node = self._not_expr()
        while self._consume_kw("AND"):
            node = ast.BinaryOp("AND", node, self._not_expr())
        return node

    def _not_expr(self):
        if self._consume_kw("NOT"):
            return ast.UnaryOp("NOT", self._not_expr())
        return self._comparison()

    def _comparison(self):
        left = self._primary()
        t = self._peek()
        if t.type == TokenType.OPERATOR:
            op = self._next().lexeme
            return ast.BinaryOp(op, *self._ip_fix(left, self._primary()))
        if t.type == TokenType.KEYWORD and t.lexeme == "LIKE":
            self._next()
            return ast.BinaryOp("LIKE", left, self._primary())
        return left

    @staticmethod
    def _ip_fix(left, right):
        """Convert an IP-string literal compared to an IP column into uint32."""
        if isinstance(left, ast.ColumnRef) and left.name in IP_COLUMNS \
                and isinstance(right, ast.Literal) and isinstance(right.value, str):
            right = ast.Literal(ip_to_int(right.value))
        elif isinstance(right, ast.ColumnRef) and right.name in IP_COLUMNS \
                and isinstance(left, ast.Literal) and isinstance(left.value, str):
            left = ast.Literal(ip_to_int(left.value))
        return left, right

    def _primary(self):
        t = self._peek()
        if t.type == TokenType.LPAREN:
            self._next()
            node = self._expr()
            self._expect(TokenType.RPAREN)
            return node
        if t.type in (TokenType.INTEGER, TokenType.FLOAT, TokenType.STRING):
            self._next()
            return ast.Literal(t.value)
        if t.type == TokenType.IDENTIFIER:
            self._next()
            return ast.ColumnRef(t.lexeme)
        raise SQLSyntaxError(f"unexpected {t.type.name} {t.lexeme!r}")


def parse(sql: str) -> ast.SelectNode:
    return Parser(tokenize(sql)).parse()
