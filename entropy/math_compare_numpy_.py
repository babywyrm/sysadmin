#!/usr/bin/env python3
"""
Extended Entropy Computation & Benchmarking
-------------------------------------------
- Supports raw labels, counts, or probabilities
- Optional GPU acceleration with CuPy
- Benchmark harness for small/medium/large datasets
- Optional matplotlib visualization of runtime scaling
"""

import numpy as np
import timeit
import pandas as pd
import matplotlib.pyplot as plt

try:
    import cupy as cp
    HAS_CUPY = True
except ImportError:
    HAS_CUPY = False


def entropy_np(
    labels,
    base=None,
    from_counts=False,
    from_probs=False,
    use_gpu=False
):
    """
    Compute Shannon entropy of a label distribution.

    Parameters
    ----------
    labels : array-like
        Input labels, counts, or probabilities depending on flags.
    base : float, optional
        Logarithm base. Defaults to natural log (e).
    from_counts : bool, optional
        If True, interpret `labels` as counts instead of raw labels.
    from_probs : bool, optional
        If True, interpret `labels` as probabilities (must sum to 1).
    use_gpu : bool, optional
        If True and CuPy is installed, computation runs on GPU.

    Returns
    -------
    float
        Entropy value.
    """
    xp = cp if (use_gpu and HAS_CUPY) else np
    labels = xp.asarray(labels)

    # Case 1: probabilities directly given
    if from_probs:
        probs = labels.astype(float)
        probs = probs[probs > 0]  # remove zeros to avoid log issues
    # Case 2: counts given
    elif from_counts:
        counts = labels.astype(int)
        if counts.sum() == 0:
            return 0.0
        probs = counts / counts.sum()
    # Case 3: raw labels
    else:
        if labels.size <= 1:
            return 0.0
        _, counts = xp.unique(labels, return_counts=True)
        probs = counts / counts.sum()

    if probs.size <= 1:
        return 0.0

    log_fn = xp.log if base is None else (lambda x: xp.log(x) / xp.log(base))
    ent = -(probs * log_fn(probs)).sum()

    return float(ent.get() if use_gpu and HAS_CUPY else ent)


def run_benchmarks():
    """Benchmark entropy implementations across dataset sizes."""
    datasets = {
        "small": np.random.randint(0, 5, 100),
        "medium": np.random.randint(0, 50, 10_000),
        "large": np.random.randint(0, 100, 1_000_000),
    }

    benchmarks = {}

    for name, data in datasets.items():
        benchmarks[name] = {}

        # Raw labels
        t_raw = timeit.timeit(lambda: entropy_np(data, base=2), number=5)
        benchmarks[name]["raw_labels"] = t_raw

        # From counts
        _, counts = np.unique(data, return_counts=True)
        t_counts = timeit.timeit(lambda: entropy_np(counts, from_counts=True, base=2), number=5)
        benchmarks[name]["from_counts"] = t_counts

        # From probabilities
        probs = counts / counts.sum()
        t_probs = timeit.timeit(lambda: entropy_np(probs, from_probs=True, base=2), number=5)
        benchmarks[name]["from_probs"] = t_probs

        # GPU acceleration (if available)
        if HAS_CUPY:
            t_gpu = timeit.timeit(lambda: entropy_np(data, base=2, use_gpu=True), number=5)
            benchmarks[name]["gpu"] = t_gpu

    df = pd.DataFrame(benchmarks)
    return df


def plot_results(df):
    """Plot benchmark results for scaling comparison."""
    ax = df.plot(kind="bar", figsize=(10, 6), logy=True)
    ax.set_title("Entropy Function Benchmark Comparison (log scale)")
    ax.set_ylabel("Runtime (seconds, lower is better)")
    ax.set_xlabel("Method")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    # Example usage
    labels = [1, 2, 2, 3, 3, 3]

    print("From raw labels:", entropy_np(labels, base=2))
    print("From counts:", entropy_np([1, 2, 3], from_counts=True, base=2))
    print("From probs:", entropy_np([0.1667, 0.3333, 0.5], from_probs=True, base=2))

    if HAS_CUPY:
        print("GPU accelerated:", entropy_np(labels, base=2, use_gpu=True))

    # Run benchmarks
    df_results = run_benchmarks()
    print("\nBenchmark Results:\n", df_results)

    # Plot results
    plot_results(df_results)

##
##
