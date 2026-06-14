"""AST node types for a PacketQL query. Pure data, like QueryX's AST."""

from __future__ import annotations

from dataclasses import dataclass, field

from .lexer import TokenType


@dataclass(frozen=True)
class Star:
    """``SELECT *``"""


@dataclass(frozen=True)
class Column:
    name: str


@dataclass(frozen=True)
class Literal:
    value: object   # int or str


@dataclass(frozen=True)
class Comparison:
    op: TokenType
    left: object
    right: object


@dataclass(frozen=True)
class Like:
    """``column LIKE 'prefix%'`` — only a trailing ``%`` (prefix match) is supported."""
    left: object
    right: object


@dataclass(frozen=True)
class And:
    left: object
    right: object


@dataclass(frozen=True)
class Or:
    left: object
    right: object


@dataclass(frozen=True)
class Not:
    operand: object


@dataclass(frozen=True)
class OrderItem:
    column: str
    descending: bool = False


@dataclass(frozen=True)
class Select:
    columns: list           # [Column, ...] or [Star]
    table: str
    where: object = None
    order_by: list = field(default_factory=list)   # [OrderItem, ...]
    limit: object = None    # int or None

    @property
    def star(self) -> bool:
        return len(self.columns) == 1 and isinstance(self.columns[0], Star)
