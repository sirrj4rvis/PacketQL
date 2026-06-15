"""AST node types for a PacketQL query (pure data)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ColumnRef:
    name: str


@dataclass(frozen=True)
class Literal:
    value: object        # int, float, or str (IP-string literals become int in the parser)


@dataclass(frozen=True)
class Aggregate:
    func: str            # COUNT, SUM, AVG, MIN, MAX
    arg: object          # column name (str), or None for COUNT(*)

    @property
    def label(self) -> str:
        return f"{self.func}(*)" if self.arg is None else f"{self.func}({self.arg})"


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
    columns: list                       # items: column-name str, "*", or Aggregate
    table: str
    where: object = None
    distinct: bool = False
    group_by: list = field(default_factory=list)
    having: object = None
    order_by: object = None             # OrderBy | None
    limit: object = None                # int | None

    @property
    def star(self) -> bool:
        return self.columns == ["*"]


@dataclass(frozen=True)
class Explain:
    select: SelectNode
