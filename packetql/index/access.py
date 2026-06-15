"""Index access path: materialise the candidate rows and apply the residual.

The planner already produced the candidate row indices (index lookups +
intersection). Here we read just those rows for the needed columns (O(1) seeks),
drop any that fail the residual predicate, and return the surviving rows in
read-column order. Aggregation / projection / ordering happen back in the
executor's `_finish`, identical to the scan path.
"""

from __future__ import annotations

from packetql.query.executor import evaluate_mask


def filtered_rows(store, plan):
    candidates = plan.access[1]
    read = plan.read_columns
    cols = {c: store.read_rows(c, candidates) for c in read}
    m = len(candidates)
    if plan.where is not None:
        mask = evaluate_mask(plan.where, cols, m)
        keep = [k for k in range(m) if mask[k]]
    else:
        keep = range(m)
    return [tuple(cols[c][k] for c in read) for k in keep]
