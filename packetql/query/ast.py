"""AST node types for a PacketQL query (pure data)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ColumnRef:
    name: str


@dataclass(frozen=True)
class Literal:
    value: object        # int, float, or str (IP-string literals become int in the parser)


@dataclass(frozen=True)
class BinaryOp:
    op: str              # '=','!=','<','>','<=','>=','AND','OR','LIKE'
    left: object
    right: object


@dataclass(frozen=True)
class UnaryOp:
    op: str              # 'NOT'
    operand: object


@dataclass(frozen=True)
class OrderBy:
    column: str
    descending: bool = False


@dataclass(frozen=True)
class SelectNode:
    columns: list        # list[str] of column names, or ["*"]
    table: str
    where: object = None
    order_by: object = None     # OrderBy | None
    limit: object = None        # int | None

    @property
    def star(self) -> bool:
        return self.columns == ["*"]
