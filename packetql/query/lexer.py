"""Hand-written lexer for PacketQL's SQL-like language (same design as QueryX).

Turns query text into a flat token stream. Supported: the keywords below, the
comparison operators ``= != <> < > <= >=``, ``* , ( )``, integer literals,
single-quoted string literals (with ``''`` as an escaped quote), and
identifiers. A trailing ``;`` is ignored. Negative literals are out of scope
(no packet field is negative).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class TokenType(Enum):
    SELECT = auto(); FROM = auto(); WHERE = auto(); ORDER = auto(); BY = auto()
    LIMIT = auto(); ASC = auto(); DESC = auto(); AND = auto(); OR = auto(); NOT = auto(); LIKE = auto()
    STAR = auto(); COMMA = auto(); LPAREN = auto(); RPAREN = auto()
    EQ = auto(); NEQ = auto(); LT = auto(); GT = auto(); LTE = auto(); GTE = auto()
    IDENT = auto(); NUMBER = auto(); STRING = auto(); EOF = auto()


_KEYWORDS = {name: TokenType[name] for name in (
    "SELECT", "FROM", "WHERE", "ORDER", "BY", "LIMIT", "ASC", "DESC", "AND", "OR", "NOT", "LIKE")}

_TWO_CHAR = {"<=": TokenType.LTE, ">=": TokenType.GTE, "<>": TokenType.NEQ, "!=": TokenType.NEQ}
_ONE_CHAR = {"=": TokenType.EQ, "<": TokenType.LT, ">": TokenType.GT, "*": TokenType.STAR,
             ",": TokenType.COMMA, "(": TokenType.LPAREN, ")": TokenType.RPAREN}


@dataclass(frozen=True)
class Token:
    type: TokenType
    lexeme: str
    value: object = None   # int for NUMBER, decoded str for STRING
    pos: int = 0


class SQLSyntaxError(Exception):
    """A lexing or parsing error, with the offending position."""


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == ";":
            i += 1  # tolerate a trailing statement terminator
        elif c == "'":
            j, buf = i + 1, []
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":  # '' -> literal quote
                        buf.append("'"); j += 2; continue
                    break
                buf.append(text[j]); j += 1
            if j >= n:
                raise SQLSyntaxError(f"unterminated string literal at position {i}")
            tokens.append(Token(TokenType.STRING, text[i:j + 1], "".join(buf), i))
            i = j + 1
        elif c.isdigit():
            j = i
            while j < n and text[j].isdigit():
                j += 1
            tokens.append(Token(TokenType.NUMBER, text[i:j], int(text[i:j]), i))
            i = j
        elif c.isalpha() or c == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            word = text[i:j]
            tokens.append(Token(_KEYWORDS.get(word.upper(), TokenType.IDENT), word, None, i))
            i = j
        elif text[i:i + 2] in _TWO_CHAR:
            tokens.append(Token(_TWO_CHAR[text[i:i + 2]], text[i:i + 2], None, i))
            i += 2
        elif c in _ONE_CHAR:
            tokens.append(Token(_ONE_CHAR[c], c, None, i))
            i += 1
        else:
            raise SQLSyntaxError(f"unexpected character {c!r} at position {i}")
    tokens.append(Token(TokenType.EOF, "", None, n))
    return tokens
