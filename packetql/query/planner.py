"""Query planner: column pruning + cost estimation (and, in Phase 4, index choice).

It determines exactly which columns must be read (SELECT ∪ WHERE ∪ ORDER BY) so
the executor never touches the others, and estimates the cost of the access path
in bytes read. The chosen plan and its cost are reported on the result so they
can be logged / shown (a mini EXPLAIN).
"""

from __future__ import annotations

from dataclasses import dataclass

from packetql.query import ast
from packetql.storage.columnar import COLUMN_NAMES, WIDTHS


class QueryError(Exception):
    pass


@dataclass
class Plan:
    out_columns: list
    read_columns: list
    where: object
    order_by: object
    limit: object
    access: tuple        # ("scan",) or ("index", kind, column, op, value)
    cost: float
    description: str


def columns_in(expr) -> set[str]:
    if expr is None or isinstance(expr, ast.Literal):
        return set()
    if isinstance(expr, ast.ColumnRef):
        return {expr.name}
    if isinstance(expr, ast.BinaryOp):
        return columns_in(expr.left) | columns_in(expr.right)
    if isinstance(expr, ast.UnaryOp):
        return columns_in(expr.operand)
    return set()


def plan_query(select, store, indexes=None) -> Plan:
    if select.table != "packets":
        raise QueryError(f"unknown table {select.table!r} (the only table is 'packets')")
    valid = set(store.column_names())
    out_columns = store.column_names() if select.star else list(select.columns)
    referenced = set(out_columns) | columns_in(select.where) | (
        {select.order_by.column} if select.order_by else set())
    for name in referenced:
        if name not in valid:
            raise QueryError(f"no such column {name!r}; columns: {', '.join(COLUMN_NAMES)}")
    read_columns = [c for c in COLUMN_NAMES if c in referenced]   # stable column order

    scan_cost = store.row_count * sum(WIDTHS[c] for c in read_columns)
    plan = Plan(out_columns, read_columns, select.where, select.order_by, select.limit,
                ("scan",), scan_cost, f"SeqScan (est. {scan_cost} B; reads {len(read_columns)}/9 columns)")

    if indexes is not None:
        _consider_index(plan, select.where, store, indexes, scan_cost)
    return plan


def _consider_index(plan, where, store, indexes, scan_cost) -> None:
    """Phase 4 hook: pick an index access path when it's cheaper than a scan.

    Filled in once the index layer exists; for now (no indexes / Phase 3) the
    plan stays a SeqScan.
    """
    chooser = getattr(indexes, "choose", None)
    if chooser is None:
        return
    chosen = chooser(where, store, scan_cost)        # -> (access, cost, residual, desc) | None
    if chosen is not None:
        access, cost, residual, desc = chosen
        plan.access, plan.cost, plan.where, plan.description = access, cost, residual, desc
