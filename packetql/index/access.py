"""Execute an index access path.

The planner already produced the candidate row indices (the index lookups +
intersection). Here we materialise just those rows for the needed columns via
the store's O(1) random access, apply any residual predicate, then reuse the
executor's order/limit/project stage.
"""

from __future__ import annotations

from packetql.query.executor import _order_limit_project, evaluate_mask


def index_path(store, plan, indexes):
    candidates = plan.access[1]
    read = plan.read_columns
    cols = {c: store.read_rows(c, candidates) for c in read}
    m = len(candidates)

    if plan.where is not None:                       # residual predicate
        mask = evaluate_mask(plan.where, cols, m)
        keep = [k for k in range(m) if mask[k]]
    else:
        keep = range(m)

    col_index = {c: i for i, c in enumerate(read)}
    rows = (tuple(cols[c][k] for c in read) for k in keep)
    return _order_limit_project(rows, plan, col_index)
