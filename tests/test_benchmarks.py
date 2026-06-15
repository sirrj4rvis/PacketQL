"""Smoke tests for the benchmark suite: it runs and the qualitative results hold.
No machine-specific timings are asserted."""

from benchmarks.benchmark_suite import (columnar_vs_rowstore, concurrency,
                                        scan_vs_index, write_throughput)


def test_scan_vs_index_runs():
    n, scan_ms, idx_ms, matches = scan_vs_index([2000])[0]
    assert n == 2000 and scan_ms > 0 and idx_ms >= 0 and matches > 0


def test_columnar_reads_less_than_rowstore():
    _n, _col_ms, _row_ms, col_bytes, row_bytes = columnar_vs_rowstore(5000)
    assert col_bytes < row_bytes        # one column vs a full row store


def test_larger_write_batch_is_faster():
    res = dict((bs, pps) for bs, pps, _mbs in write_throughput(500, [1, 500]))
    assert res[500] > res[1]            # fewer fsyncs -> higher throughput


def test_concurrency_runs():
    res = concurrency(500, [1, 2], duration=0.1)
    assert all(qps > 0 for _c, qps in res)
