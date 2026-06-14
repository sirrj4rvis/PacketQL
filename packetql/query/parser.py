"""Recursive-descent parser → Select AST (same structure as QueryX's parser).

Grammar (one method per rule; precedence falls out of the layering):

    select      ::= "SELECT" select_list "FROM" ident
                    [ "WHERE" expr ]
                    [ "ORDER" "BY" order_item { "," order_item } ]
                    [ "LIMIT" number ]
    select_list ::= "*" | ident { "," ident }
    order_item  ::= ident [ "ASC" | "DESC" ]
    expr        ::= or_expr
    or_expr     ::= and_expr { "OR" and_expr }
    and_expr    ::= not_expr { "AND" not_expr }
    not_expr    ::= "NOT" not_expr | comparison
    comparison  ::= primary [ ( "=" | "!=" | "<>" | "<" | ">" | "<=" | ">=" ) primary ]
    primary     ::= "(" expr ")" | number | string | ident
"""

from __future__ import annotations

from . import ast
from .lexer import SQLSyntaxError, TokenType, tokenize

_COMPARISONS = {TokenType.EQ, TokenType.NEQ, TokenType.LT, TokenType.GT, TokenType.LTE, TokenType.GTE}


class Parser:
    def __init__(self, tokens) -> None:
        self._toks = tokens
        self._pos = 0

    # -- token helpers ------------------------------------------------------
    def _peek(self):
        return self._toks[self._pos]

    def _at(self, tt) -> bool:
        return self._peek().type == tt

    def _advance(self):
        tok = self._toks[self._pos]
        self._pos += 1
        return tok

    def _expect(self, tt):
        tok = self._peek()
        if tok.type != tt:
            raise SQLSyntaxError(f"expected {tt.name}, got {tok.type.name} ({tok.lexeme!r})")
        return self._advance()

    # -- grammar ------------------------------------------------------------
    def parse(self) -> ast.Select:
        self._expect(TokenType.SELECT)
        columns = self._select_list()
        self._expect(TokenType.FROM)
        table = self._expect(TokenType.IDENT).lexeme
        where = None
        if self._at(TokenType.WHERE):
            self._advance()
            where = self._expr()
        order_by = []
        if self._at(TokenType.ORDER):
            self._advance()
            self._expect(TokenType.BY)
            order_by = self._order_list()
        limit = None
        if self._at(TokenType.LIMIT):
            self._advance()
            limit = self._expect(TokenType.NUMBER).value
        self._expect(TokenType.EOF)
        return ast.Select(columns, table, where, order_by, limit)

    def _select_list(self):
        if self._at(TokenType.STAR):
            self._advance()
            return [ast.Star()]
        cols = [ast.Column(self._expect(TokenType.IDENT).lexeme)]
        while self._at(TokenType.COMMA):
            self._advance()
            cols.append(ast.Column(self._expect(TokenType.IDENT).lexeme))
        return cols

    def _order_list(self):
        items = [self._order_item()]
        while self._at(TokenType.COMMA):
            self._advance()
            items.append(self._order_item())
        return items

    def _order_item(self):
        name = self._expect(TokenType.IDENT).lexeme
        descending = False
        if self._at(TokenType.ASC):
            self._advance()
        elif self._at(TokenType.DESC):
            self._advance()
            descending = True
        return ast.OrderItem(name, descending)

    def _expr(self):
        return self._or_expr()

    def _or_expr(self):
        node = self._and_expr()
        while self._at(TokenType.OR):
            self._advance()
            node = ast.Or(node, self._and_expr())
        return node

    def _and_expr(self):
        node = self._not_expr()
        while self._at(TokenType.AND):
            self._advance()
            node = ast.And(node, self._not_expr())
        return node

    def _not_expr(self):
        if self._at(TokenType.NOT):
            self._advance()
            return ast.Not(self._not_expr())
        return self._comparison()

    def _comparison(self):
        left = self._primary()
        if self._peek().type in _COMPARISONS:
            op = self._advance().type
            return ast.Comparison(op, left, self._primary())
        if self._at(TokenType.LIKE):
            self._advance()
            return ast.Like(left, self._primary())
        return left

    def _primary(self):
        tok = self._peek()
        if tok.type == TokenType.LPAREN:
            self._advance()
            node = self._expr()
            self._expect(TokenType.RPAREN)
            return node
        if tok.type in (TokenType.NUMBER, TokenType.STRING):
            self._advance()
            return ast.Literal(tok.value)
        if tok.type == TokenType.IDENT:
            self._advance()
            return ast.Column(tok.lexeme)
        raise SQLSyntaxError(f"unexpected {tok.type.name} ({tok.lexeme!r})")


def parse(sql: str) -> ast.Select:
    return Parser(tokenize(sql)).parse()
