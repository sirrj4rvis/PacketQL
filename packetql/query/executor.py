"""Vectorized executor: a generator pipeline that processes rows in batches.

The scan/filter stages work on **batches of 1024 values at a time** (Python
lists, column-at-a-time), not row-at-a-time — the same shape DuckDB/ClickHouse
use. The pipeline is scan -> filter -> (order / limit) -> project, each stage a
generator. ORDER BY ... LIMIT N keeps a bounded min-heap (O(m log N)) instead of
a full sort. An index access path (Phase 4) replaces the scan/filter front with
an index lookup, then projects the selected rows.
"""

from __future__ import annotations

import itertools
import operator
from dataclasses import dataclass

from packetql.index.topn import top_n
from packetql.query import ast
from packetql.query.parser import parse
from packetql.query.planner import QueryError, plan_query

_CMP = {
    "=": operator.eq, "!=": operator.ne, "<": operator.lt,
    ">": operator.gt, "<=": operator.le, ">=": operator.ge,
}


@dataclass
class QueryResult:
    columns: list
    rows: list
    plan: str = ""

    def __iter__(self):
        return iter(self.rows)

    def __len__(self):
        return len(self.rows)


def ip_prefix_range(pattern: str) -> tuple[int, int]:
    """`'192.168.%'` -> the inclusive uint32 range [192.168.0.0, 192.168.255.255]."""
    core = pattern[:-1] if pattern.endswith("%") else pattern
    known = [int(p) for p in core.split(".") if p != ""]
    low = high = 0
    for k in range(4):
        if k < len(known):
            low = (low << 8) | known[k]
            high = (high << 8) | known[k]
        else:
            low = low << 8
            high = (high << 8) | 255
    return low, high


def _vector(node, batch, n):
    if isinstance(node, ast.ColumnRef):
        return batch[node.name]
    if isinstance(node, ast.Literal):
        return [node.value] * n
    raise QueryError("invalid operand in WHERE")


def evaluate_mask(expr, batch, n) -> list[bool]:
    """Vectorized predicate evaluation over a batch -> a boolean mask."""
    if isinstance(expr, ast.BinaryOp):
        if expr.op in _CMP:
            op = _CMP[expr.op]
            left, right = _vector(expr.left, batch, n), _vector(expr.right, batch, n)
            return [op(a, b) for a, b in zip(left, right)]
        if expr.op == "AND":
            a = evaluate_mask(expr.left, batch, n)
            b = evaluate_mask(expr.right, batch, n)
            return [x and y for x, y in zip(a, b)]
        if expr.op == "OR":
            a = evaluate_mask(expr.left, batch, n)
            b = evaluate_mask(expr.right, batch, n)
            return [x or y for x, y in zip(a, b)]
        if expr.op == "LIKE":
            low, high = ip_prefix_range(expr.right.value)
            return [low <= v <= high for v in batch[expr.left.name]]
    if isinstance(expr, ast.UnaryOp) and expr.op == "NOT":
        return [not x for x in evaluate_mask(expr.operand, batch, n)]
    raise QueryError("invalid WHERE expression")


def _scan_batches(store, read_columns, batch_rows=1024):
    """Yield {column: [values]} dicts, 1024 rows at a time, for the needed columns."""
    gens = [store.iter_column(c, batch_rows) for c in read_columns]
    while True:
        try:
            cols = [next(g) for g in gens]
        except StopIteration:
            return
        yield dict(zip(read_columns, cols))


def _scan_path(store, plan):
    read = plan.read_columns
    col_index = {c: i for i, c in enumerate(read)}

    def filtered_rows():
        for batch in _scan_batches(store, read):
            n = len(batch[read[0]])
            mask = evaluate_mask(plan.where, batch, n) if plan.where is not None else None
            for i in range(n):
                if mask is None or mask[i]:
                    yield tuple(batch[c][i] for c in read)

    return _order_limit_project(filtered_rows(), plan, col_index)


def _order_limit_project(rows, plan, col_index):
    if plan.order_by is not None:
        oi = col_index[plan.order_by.column]
        if plan.limit is not None:
            kept = top_n(rows, plan.limit, key=lambda r: r[oi], largest=plan.order_by.descending)
        else:
            kept = sorted(rows, key=lambda r: r[oi], reverse=plan.order_by.descending)
    elif plan.limit is not None:
        kept = list(itertools.islice(rows, plan.limit))
    else:
        kept = list(rows)
    out = [col_index[c] for c in plan.out_columns]
    return [tuple(r[j] for j in out) for r in kept]


def run_query(store, sql: str, indexes=None) -> QueryResult:
    select = parse(sql)
    plan = plan_query(select, store, indexes)
    if plan.access[0] == "scan":
        rows = _scan_path(store, plan)
    else:
        from packetql.index.access import index_path     # Phase 4
        rows = index_path(store, plan, indexes)
    return QueryResult(plan.out_columns, rows, plan.description)
