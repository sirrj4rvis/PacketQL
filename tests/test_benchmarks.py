"""Smoke tests for the benchmark suite: it runs and produces sane numbers.

Deliberately does NOT assert machine-specific timings (those vary run to run);
only structural facts that must always hold.
"""

from benchmarks.benchmark_suite import run_benchmarks


def test_benchmark_suite_runs():
    r = run_benchmarks(n=2000, reps=2, write_report=False, quiet=True)
    assert r["captured"] == 2000
    assert r["dropped"] == 0
    assert r["cap_throughput"] > 0
    assert r["matches_eq"] > 0          # some packets are dst_port 443


def test_selective_read_is_a_fraction_of_the_store():
    r = run_benchmarks(n=2000, reps=2, write_report=False, quiet=True)
    assert 0 < r["sel_bytes"] < r["total_bytes"]
