"""Query planner: column pruning + cost estimation (+ index choice via the
index layer's `choose`). It collects exactly the stored columns a query needs —
across SELECT items, WHERE, GROUP BY, HAVING (incl. aggregate arguments), and a
non-aggregated ORDER BY — so the executor reads nothing extra, and estimates the
access cost in bytes (a mini EXPLAIN). Aggregation/DISTINCT/projection happen in
the executor on the filtered rows.
"""

from __future__ import annotations

from dataclasses import dataclass

from packetql.query import ast
from packetql.storage.columnar import COLUMN_NAMES, WIDTHS


class QueryError(Exception):
    pass


@dataclass
class Plan:
    read_columns: list
    where: object
    access: tuple        # ("scan",) or ("index", candidate_rows, labels)
    cost: float
    description: str


def columns_in(expr) -> set[str]:
    """Stored columns referenced by a WHERE expression (no aggregates there)."""
    if expr is None or isinstance(expr, ast.Literal):
        return set()
    if isinstance(expr, ast.ColumnRef):
        return {expr.name}
    if isinstance(expr, ast.BinaryOp):
        return columns_in(expr.left) | columns_in(expr.right)
    if isinstance(expr, ast.UnaryOp):
        return columns_in(expr.operand)
    return set()


def having_columns(expr) -> set[str]:
    """Stored columns referenced in HAVING — plain columns and aggregate args."""
    if expr is None or isinstance(expr, ast.Literal):
        return set()
    if isinstance(expr, ast.Aggregate):
        return {expr.arg} if expr.arg is not None else set()
    if isinstance(expr, ast.ColumnRef):
        return {expr.name}
    if isinstance(expr, ast.BinaryOp):
        return having_columns(expr.left) | having_columns(expr.right)
    if isinstance(expr, ast.UnaryOp):
        return having_columns(expr.operand)
    return set()


def is_aggregated(select) -> bool:
    return bool(select.group_by) or any(isinstance(c, ast.Aggregate) for c in select.columns)


def referenced_columns(select) -> set[str]:
    cols: set[str] = set()
    if select.star:
        cols |= set(COLUMN_NAMES)
    else:
        for item in select.columns:
            if isinstance(item, ast.Aggregate):
                if item.arg is not None:
                    cols.add(item.arg)
            else:
                cols.add(item)
    cols |= columns_in(select.where)
    cols |= set(select.group_by)
    cols |= having_columns(select.having)
    if select.order_by is not None and not is_aggregated(select):
        cols.add(select.order_by.column)       # a non-aggregated ORDER BY reads a real column
    return cols


def plan_query(select, store, indexes=None) -> Plan:
    if select.table != "packets":
        raise QueryError(f"unknown table {select.table!r} (the only table is 'packets')")
    valid = set(store.column_names())
    referenced = referenced_columns(select)
    for name in referenced:
        if name not in valid:
            raise QueryError(f"no such column {name!r}; columns: {', '.join(COLUMN_NAMES)}")
    read_columns = [c for c in COLUMN_NAMES if c in referenced]
    if not read_columns:
        # A query that references no stored column (e.g. `SELECT COUNT(*) FROM
        # packets` with no WHERE/GROUP BY) still needs the row source to emit one
        # row per packet. Read the narrowest column so COUNT sees every row.
        # (Without this the scan generator has zero column iterators and loops
        # forever yielding empty batches.)
        read_columns = [min(COLUMN_NAMES, key=lambda c: WIDTHS[c])]

    scan_cost = store.row_count * sum(WIDTHS[c] for c in read_columns)
    plan = Plan(read_columns, select.where, ("scan",), scan_cost,
                f"SeqScan (est. {scan_cost} B; reads {len(read_columns)}/{len(COLUMN_NAMES)} columns)")

    if indexes is not None and select.where is not None:
        chooser = getattr(indexes, "choose", None)
        if chooser is not None:
            chosen = chooser(select.where, store, scan_cost)
            if chosen is not None:
                access, cost, residual, desc = chosen
                plan.access, plan.cost, plan.where, plan.description = access, cost, residual, desc
    return plan
