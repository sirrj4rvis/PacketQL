"""Execute a parsed query against a columnar store, optionally using indexes.

Two defining traits:

* **Column pruning** — only the columns a query references (SELECT, residual
  WHERE, ORDER BY) are read from disk.
* **A small planner** — when indexes are supplied, the executor inspects the
  top-level ``AND`` conjuncts and, if one is an equality on a hash-indexed column
  or a prefix ``LIKE`` on a trie-indexed IP column, it gets the candidate rows
  straight from the index and applies the remaining conjuncts as a residual
  filter (the same index-or-scan idea as QueryX). ``ORDER BY col LIMIT N`` uses a
  bounded heap instead of a full sort.

NULL semantics stay simple: a comparison (or LIKE) where either side is NULL is
false; NULLs sort last on an ascending ORDER BY (first on descending).
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field

from . import ast
from .lexer import TokenType
from .parser import parse
from packetql.index.topn import top_n


class QueryError(Exception):
    """A runtime query error: unknown table/column, or an invalid comparison."""


@dataclass
class QueryResult:
    columns: list
    rows: list
    plan: str = ""

    def __iter__(self):
        return iter(self.rows)

    def __len__(self):
        return len(self.rows)


_OPS = {
    TokenType.EQ: operator.eq, TokenType.NEQ: operator.ne,
    TokenType.LT: operator.lt, TokenType.GT: operator.gt,
    TokenType.LTE: operator.le, TokenType.GTE: operator.ge,
}


# -- predicate analysis & evaluation ----------------------------------------


def _columns_in(expr) -> set[str]:
    if expr is None or isinstance(expr, ast.Literal):
        return set()
    if isinstance(expr, ast.Column):
        return {expr.name}
    if isinstance(expr, (ast.Comparison, ast.Like)):
        return _columns_in(expr.left) | _columns_in(expr.right)
    if isinstance(expr, (ast.And, ast.Or)):
        return _columns_in(expr.left) | _columns_in(expr.right)
    if isinstance(expr, ast.Not):
        return _columns_in(expr.operand)
    return set()


def _value(node, data, i):
    if isinstance(node, ast.Column):
        return data[node.name][i]
    if isinstance(node, ast.Literal):
        return node.value
    raise QueryError("invalid operand in WHERE clause")


def _like(value, pattern) -> bool:
    if value is None or pattern is None:
        return False
    if not isinstance(value, str) or not isinstance(pattern, str):
        raise QueryError("LIKE requires text operands")
    if pattern.endswith("%"):
        return value.startswith(pattern[:-1])
    return value == pattern


def _eval(expr, data, i) -> bool:
    if isinstance(expr, ast.Comparison):
        left, right = _value(expr.left, data, i), _value(expr.right, data, i)
        if left is None or right is None:
            return False
        try:
            return _OPS[expr.op](left, right)
        except TypeError:
            raise QueryError(f"cannot compare {left!r} and {right!r} (type mismatch)")
    if isinstance(expr, ast.Like):
        return _like(_value(expr.left, data, i), _value(expr.right, data, i))
    if isinstance(expr, ast.And):
        return _eval(expr.left, data, i) and _eval(expr.right, data, i)
    if isinstance(expr, ast.Or):
        return _eval(expr.left, data, i) or _eval(expr.right, data, i)
    if isinstance(expr, ast.Not):
        return not _eval(expr.operand, data, i)
    raise QueryError("WHERE must be a comparison/LIKE, optionally combined with AND/OR/NOT")


# -- planning ----------------------------------------------------------------


def _conjuncts(expr) -> list:
    """Flatten a top-level AND chain into its conjuncts (others pass through whole)."""
    if isinstance(expr, ast.And):
        return _conjuncts(expr.left) + _conjuncts(expr.right)
    return [expr]


def _rebuild_and(conjuncts) -> object:
    if not conjuncts:
        return None
    node = conjuncts[0]
    for c in conjuncts[1:]:
        node = ast.And(node, c)
    return node


def _eq_on_hash(conj, indexes):
    """If ``conj`` is ``col = literal`` (either order) on a hash-indexed column,
    return (column, value); else None."""
    if isinstance(conj, ast.Comparison) and conj.op == TokenType.EQ:
        left, right = conj.left, conj.right
        if isinstance(left, ast.Column) and isinstance(right, ast.Literal) and left.name in indexes.hash:
            return left.name, right.value
        if isinstance(right, ast.Column) and isinstance(left, ast.Literal) and right.name in indexes.hash:
            return right.name, left.value
    return None


def _prefix_on_trie(conj, indexes):
    """If ``conj`` is ``col LIKE 'a.b.c.%'`` on a trie-indexed column at an octet
    boundary, return (column, octets); else None."""
    if isinstance(conj, ast.Like) and isinstance(conj.left, ast.Column) and isinstance(conj.right, ast.Literal):
        col, pattern = conj.left.name, conj.right.value
        if col in indexes.trie and isinstance(pattern, str) and pattern.endswith(".%"):
            octets = [int(p) for p in pattern[:-1].split(".") if p]
            return col, octets
    return None


def _plan(where, indexes):
    """Return (candidate_rows | None, residual_predicate, plan_label)."""
    conjuncts = _conjuncts(where)
    for k, conj in enumerate(conjuncts):
        eq = _eq_on_hash(conj, indexes)
        if eq is not None:
            col, value = eq
            cand = indexes.hash[col].lookup(value)
            return cand, _rebuild_and(conjuncts[:k] + conjuncts[k + 1:]), f"HashIndex on {col}"
        prefix = _prefix_on_trie(conj, indexes)
        if prefix is not None:
            col, octets = prefix
            cand = indexes.trie[col].prefix(octets)
            return cand, _rebuild_and(conjuncts[:k] + conjuncts[k + 1:]), f"TrieScan on {col}"
    return None, where, None


# -- execution ---------------------------------------------------------------


def _order_key(values):
    """Sort key that places NULLs last on ascending order (first on descending)."""
    return lambda i: (values[i] is None, values[i] if values[i] is not None else 0)


def run_query(store, sql: str, indexes=None) -> QueryResult:
    """Parse and run ``sql`` against ``store``; use ``indexes`` if they help."""
    select = parse(sql)
    if select.table != "packets":
        raise QueryError(f"unknown table {select.table!r} (the only table is 'packets')")

    valid = store.column_names()
    out_cols = list(valid) if select.star else [c.name for c in select.columns]

    candidates, residual, plan_label = (None, select.where, None)
    if indexes is not None and select.where is not None:
        candidates, residual, plan_label = _plan(select.where, indexes)

    referenced = set(out_cols) | _columns_in(residual) | {o.column for o in select.order_by}
    for name in referenced:
        if name not in valid:
            raise QueryError(f"no such column {name!r}; columns are: {', '.join(valid)}")
    data = {name: store.column(name) for name in referenced}

    idx = list(candidates) if candidates is not None else list(range(store.row_count))
    if residual is not None:
        idx = [i for i in idx if _eval(residual, data, i)]

    # ORDER BY (+ LIMIT). Single key + limit -> bounded heap; otherwise full sort.
    if select.order_by:
        if len(select.order_by) == 1 and select.limit is not None:
            item = select.order_by[0]
            key = _order_key(data[item.column])
            idx = top_n(idx, select.limit, key, largest=item.descending)
        else:
            for item in reversed(select.order_by):
                idx.sort(key=_order_key(data[item.column]), reverse=item.descending)
            if select.limit is not None:
                idx = idx[:select.limit]
    elif select.limit is not None:
        idx = idx[:select.limit]

    rows = [tuple(data[c][i] for c in out_cols) for i in idx]

    plan = plan_label or "SeqScan"
    if select.order_by and len(select.order_by) == 1 and select.limit is not None:
        plan += f"; Top-{select.limit} heap on {select.order_by[0].column}"
    return QueryResult(out_cols, rows, plan=plan)
