"""Hand-written SQL-like lexer (no regex, no generator tools).

Token types per the spec: KEYWORD, IDENTIFIER, INTEGER, FLOAT, STRING, OPERATOR,
STAR, COMMA, LPAREN, RPAREN, EOF. Operators: = != <> < > <= >=. Keywords include
the logical AND/OR/NOT and LIKE. A trailing ';' is ignored.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class TokenType(Enum):
    KEYWORD = auto()
    IDENTIFIER = auto()
    INTEGER = auto()
    FLOAT = auto()
    STRING = auto()
    OPERATOR = auto()
    STAR = auto()
    COMMA = auto()
    LPAREN = auto()
    RPAREN = auto()
    EOF = auto()


_KEYWORDS = {"SELECT", "FROM", "WHERE", "ORDER", "BY", "LIMIT", "ASC", "DESC", "AND", "OR", "NOT", "LIKE"}
_TWO_CHAR = {"<=", ">=", "!=", "<>"}
_ONE_CHAR = {"=", "<", ">"}


@dataclass(frozen=True)
class Token:
    type: TokenType
    lexeme: str
    value: object = None     # int (INTEGER), float (FLOAT), decoded str (STRING)
    pos: int = 0


class SQLSyntaxError(Exception):
    pass


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace() or c == ";":
            i += 1
        elif c == "'":
            j, buf = i + 1, []
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        buf.append("'"); j += 2; continue
                    break
                buf.append(text[j]); j += 1
            if j >= n:
                raise SQLSyntaxError(f"unterminated string literal at {i}")
            tokens.append(Token(TokenType.STRING, text[i:j + 1], "".join(buf), i))
            i = j + 1
        elif c.isdigit():
            j = i
            while j < n and text[j].isdigit():
                j += 1
            if j < n and text[j] == ".":
                j += 1
                while j < n and text[j].isdigit():
                    j += 1
                tokens.append(Token(TokenType.FLOAT, text[i:j], float(text[i:j]), i))
            else:
                tokens.append(Token(TokenType.INTEGER, text[i:j], int(text[i:j]), i))
            i = j
        elif c.isalpha() or c == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            word = text[i:j]
            up = word.upper()
            if up in _KEYWORDS:
                tokens.append(Token(TokenType.KEYWORD, up, None, i))
            else:
                tokens.append(Token(TokenType.IDENTIFIER, word, None, i))
            i = j
        elif c == "*":
            tokens.append(Token(TokenType.STAR, "*", None, i)); i += 1
        elif c == ",":
            tokens.append(Token(TokenType.COMMA, ",", None, i)); i += 1
        elif c == "(":
            tokens.append(Token(TokenType.LPAREN, "(", None, i)); i += 1
        elif c == ")":
            tokens.append(Token(TokenType.RPAREN, ")", None, i)); i += 1
        elif text[i:i + 2] in _TWO_CHAR:
            two = text[i:i + 2]
            tokens.append(Token(TokenType.OPERATOR, "!=" if two == "<>" else two, None, i)); i += 2
        elif c in _ONE_CHAR:
            tokens.append(Token(TokenType.OPERATOR, c, None, i)); i += 1
        else:
            raise SQLSyntaxError(f"unexpected character {c!r} at {i}")
    tokens.append(Token(TokenType.EOF, "", None, n))
    return tokens
