"""Vectorized executor with aggregation, DISTINCT, and EXPLAIN.

Flow: a row source (vectorized scan+filter, or an index lookup) yields the
filtered rows (read-column tuples); then `_finish` either
  * **aggregates** them — hash-group by the GROUP BY key, compute COUNT/SUM/AVG/
    MIN/MAX per group, apply HAVING (ported from QueryX's HashAggregate), or
  * **projects** them — select the columns, optional DISTINCT,
and finally applies ORDER BY (+ a bounded top-N heap when LIMIT is present) and
LIMIT. `EXPLAIN` returns the plan instead of running it.
"""

from __future__ import annotations

import itertools
import operator
from dataclasses import dataclass

from packetql.index.topn import top_n
from packetql.query import ast
from packetql.query.parser import parse
from packetql.query.planner import QueryError, is_aggregated, plan_query
from packetql.storage.columnar import COLUMN_NAMES

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


# -- vectorized WHERE evaluation --------------------------------------------
def _vector(node, batch, n):
    if isinstance(node, ast.ColumnRef):
        return batch[node.name]
    if isinstance(node, ast.Literal):
        return [node.value] * n
    raise QueryError("invalid operand in WHERE")


def evaluate_mask(expr, batch, n) -> list[bool]:
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
    gens = [store.iter_column(c, batch_rows) for c in read_columns]
    while True:
        try:
            cols = [next(g) for g in gens]
        except StopIteration:
            return
        yield dict(zip(read_columns, cols))


def _scan_rows(store, plan):
    read = plan.read_columns
    for batch in _scan_batches(store, read):
        n = len(batch[read[0]]) if read else 0
        mask = evaluate_mask(plan.where, batch, n) if plan.where is not None else None
        for i in range(n):
            if mask is None or mask[i]:
                yield tuple(batch[c][i] for c in read)


# -- aggregation ------------------------------------------------------------
def _compute_agg(agg, group_rows, ridx):
    if agg.func == "COUNT":
        return len(group_rows)
    vals = [r[ridx[agg.arg]] for r in group_rows]
    if not vals:
        return 0
    if agg.func == "SUM":
        return sum(vals)
    if agg.func == "AVG":
        return sum(vals) / len(vals)
    if agg.func == "MIN":
        return min(vals)
    if agg.func == "MAX":
        return max(vals)
    raise QueryError(f"unknown aggregate {agg.func!r}")


def _having_value(node, grp, ridx, group_by):
    if isinstance(node, ast.Aggregate):
        return _compute_agg(node, grp, ridx)
    if isinstance(node, ast.Literal):
        return node.value
    if isinstance(node, ast.ColumnRef):
        if node.name not in group_by:
            raise QueryError(f"HAVING column {node.name!r} must be grouped or aggregated")
        return grp[0][ridx[node.name]]
    raise QueryError("invalid HAVING operand")


def _eval_having(expr, grp, ridx, group_by) -> bool:
    if isinstance(expr, ast.BinaryOp):
        if expr.op in _CMP:
            left = _having_value(expr.left, grp, ridx, group_by)
            right = _having_value(expr.right, grp, ridx, group_by)
            return _CMP[expr.op](left, right)
        if expr.op == "AND":
            return _eval_having(expr.left, grp, ridx, group_by) and _eval_having(expr.right, grp, ridx, group_by)
        if expr.op == "OR":
            return _eval_having(expr.left, grp, ridx, group_by) or _eval_having(expr.right, grp, ridx, group_by)
    if isinstance(expr, ast.UnaryOp) and expr.op == "NOT":
        return not _eval_having(expr.operand, grp, ridx, group_by)
    raise QueryError("invalid HAVING expression")


def _aggregate_finish(select, rows, ridx):
    if select.star:
        raise QueryError("SELECT * is not allowed with GROUP BY / aggregates")
    group_by = select.group_by
    for item in select.columns:
        if isinstance(item, str) and item not in group_by:
            raise QueryError(f"column {item!r} must appear in GROUP BY or be aggregated")
    if not group_by and any(isinstance(i, str) for i in select.columns):
        raise QueryError("cannot mix a plain column with aggregates without GROUP BY")

    gkeys = [ridx[c] for c in group_by]
    groups: dict = {}
    order: list = []
    for r in rows:
        key = tuple(r[i] for i in gkeys)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)
    if not group_by and not order:                  # scalar aggregate over zero rows -> one row
        groups[()] = []
        order = [()]

    labels = [i.label if isinstance(i, ast.Aggregate) else i for i in select.columns]
    out = []
    for key in order:
        grp = groups[key]
        if select.having is not None and not _eval_having(select.having, grp, ridx, group_by):
            continue
        row = tuple(_compute_agg(i, grp, ridx) if isinstance(i, ast.Aggregate) else grp[0][ridx[i]]
                    for i in select.columns)
        out.append(row)
    if select.distinct:
        out = _dedup(out)
    out = _order_limit_labeled(out, labels, select.order_by, select.limit)
    return labels, out


def _dedup(rows):
    seen, out = set(), []
    for r in rows:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _order_limit_labeled(rows, labels, order_by, limit):
    if order_by is not None:
        if order_by.column not in labels:
            raise QueryError(f"ORDER BY {order_by.column!r} must be a selected output column")
        oi = labels.index(order_by.column)
        rows = sorted(rows, key=lambda r: r[oi], reverse=order_by.descending)
    if limit is not None:
        rows = rows[:limit]
    return rows


def _finish(select, plan, row_source):
    ridx = {c: i for i, c in enumerate(plan.read_columns)}
    if is_aggregated(select):
        return _aggregate_finish(select, list(row_source), ridx)

    out_cols = list(COLUMN_NAMES) if select.star else list(select.columns)
    out_idx = [ridx[c] for c in out_cols]

    if select.distinct:
        projected = _dedup([tuple(r[j] for j in out_idx) for r in row_source])
        if select.order_by is not None:
            if select.order_by.column not in out_cols:
                raise QueryError(f"ORDER BY {select.order_by.column!r} must be selected when using DISTINCT")
            oi = out_cols.index(select.order_by.column)
            projected = sorted(projected, key=lambda r: r[oi], reverse=select.order_by.descending)
        if select.limit is not None:
            projected = projected[:select.limit]
        return out_cols, projected

    # order (on read columns, so ORDER BY may use unselected columns) -> limit -> project
    if select.order_by is not None:
        oi = ridx[select.order_by.column]
        if select.limit is not None:
            kept = top_n(row_source, select.limit, key=lambda r: r[oi], largest=select.order_by.descending)
        else:
            kept = sorted(row_source, key=lambda r: r[oi], reverse=select.order_by.descending)
    elif select.limit is not None:
        kept = list(itertools.islice(row_source, select.limit))
    else:
        kept = list(row_source)
    return out_cols, [tuple(r[j] for j in out_idx) for r in kept]


def _explain(select, store, indexes):
    plan = plan_query(select, store, indexes)
    lines = []
    if select.limit is not None:
        lines.append(f"Limit: {select.limit}")
    if select.order_by is not None:
        lines.append(f"Sort: {select.order_by.column}{' DESC' if select.order_by.descending else ''}")
    if select.distinct:
        lines.append("Distinct")
    if is_aggregated(select):
        gb = ", ".join(select.group_by) if select.group_by else "(scalar)"
        lines.append(f"HashAggregate: group by [{gb}]" + ("  + Having" if select.having is not None else ""))
    lines.append(plan.description)
    return QueryResult(["QUERY PLAN"], [(ln,) for ln in lines], plan=plan.description)


def run_query(store, sql: str, indexes=None) -> QueryResult:
    node = parse(sql)
    if isinstance(node, ast.Explain):
        return _explain(node.select, store, indexes)
    select = node
    plan = plan_query(select, store, indexes)
    if plan.access[0] == "scan":
        row_source = _scan_rows(store, plan)
    else:
        from packetql.index.access import filtered_rows
        row_source = filtered_rows(store, plan)
    columns, rows = _finish(select, plan, row_source)
    return QueryResult(columns, rows, plan.description)
