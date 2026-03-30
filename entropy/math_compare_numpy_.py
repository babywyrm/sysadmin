#!/usr/bin/env python3
"""
Extended Entropy Computation & Benchmarking
-------------------------------------------
- Supports raw labels, counts, or probabilities
- Optional GPU acceleration with CuPy
- Benchmark harness for small/medium/large datasets
- Optional matplotlib visualization of runtime scaling
"""

from __future__ import annotations

import timeit
from enum import Enum, auto
from typing import Literal

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from numpy.typing import ArrayLike, NDArray

try:
    import cupy as cp

    HAS_CUPY = True
except ImportError:
    HAS_CUPY = False


# ---------------------------------------------------------------------------
# Types & Enums
# ---------------------------------------------------------------------------


class InputMode(Enum):
    LABELS = auto()
    COUNTS = auto()
    PROBS = auto()


type FloatArray = NDArray[np.floating]


# ---------------------------------------------------------------------------
# Core entropy logic
# ---------------------------------------------------------------------------


def _to_probs(data: FloatArray, mode: InputMode, xp) -> FloatArray:
    """Convert raw input into a probability array."""
    match mode:
        case InputMode.PROBS:
            probs = data.astype(float)
            return probs[probs > 0]

        case InputMode.COUNTS:
            counts = data.astype(float)
            total = counts.sum()
            if total == 0:
                return xp.array([])
            return counts[counts > 0] / total

        case InputMode.LABELS:
            if data.size <= 1:
                return xp.array([])
            _, counts = xp.unique(data, return_counts=True)
            return counts / counts.sum()


def _log(
    x: FloatArray,
    base: float | None,
    xp,
) -> FloatArray:
    return xp.log(x) if base is None else xp.log(x) / xp.log(base)


def entropy(
    data: ArrayLike,
    *,
    mode: InputMode = InputMode.LABELS,
    base: float | None = None,
    use_gpu: bool = False,
) -> float:
    """
    Compute Shannon entropy of a distribution.

    Parameters
    ----------
    data:
        Input labels, counts, or probabilities depending on ``mode``.
    mode:
        One of ``InputMode.LABELS`` (default), ``InputMode.COUNTS``,
        or ``InputMode.PROBS``.
    base:
        Logarithm base. ``None`` defaults to the natural log (nats).
    use_gpu:
        If ``True`` and CuPy is installed, computation runs on the GPU.

    Returns
    -------
    float
        Entropy value. Returns ``0.0`` for degenerate distributions.

    Raises
    ------
    ValueError
        If ``use_gpu=True`` but CuPy is not installed.
    ValueError
        If ``mode`` is ``InputMode.PROBS`` and values don't sum to ~1.
    """
    if use_gpu and not HAS_CUPY:
        raise ValueError(
            "use_gpu=True requires CuPy, but it is not installed."
        )

    xp = cp if use_gpu else np
    arr: FloatArray = xp.asarray(data)

    if mode is InputMode.PROBS:
        total = float(arr.sum())
        if not np.isclose(total, 1.0, atol=1e-3):
            raise ValueError(
                f"Probabilities must sum to 1.0, got {total:.6f}."
            )

    probs = _to_probs(arr, mode, xp)

    if probs.size <= 1:
        return 0.0

    ent: float = float(-(probs * _log(probs, base, xp)).sum())
    return float(ent.get()) if use_gpu else ent  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Benchmark harness
# ---------------------------------------------------------------------------


DatasetSize = Literal["small", "medium", "large"]

_DATASET_CONFIGS: dict[DatasetSize, tuple[int, int]] = {
    "small": (5, 100),
    "medium": (50, 10_000),
    "large": (100, 1_000_000),
}

_REPEATS = 5


def _make_dataset(n_classes: int, n_samples: int) -> NDArray[np.int_]:
    return np.random.randint(0, n_classes, n_samples)


def _time(fn, repeats: int = _REPEATS) -> float:
    return timeit.timeit(fn, number=repeats)


def run_benchmarks() -> pd.DataFrame:
    """
    Benchmark ``entropy`` across dataset sizes and input modes.

    Returns
    -------
    pd.DataFrame
        Rows = methods, columns = dataset sizes.
    """
    results: dict[str, dict[DatasetSize, float]] = {}

    for size, (n_classes, n_samples) in _DATASET_CONFIGS.items():
        data = _make_dataset(n_classes, n_samples)
        _, counts = np.unique(data, return_counts=True)
        probs = counts / counts.sum()

        rows: dict[str, float] = {
            "labels": _time(
                lambda: entropy(data, mode=InputMode.LABELS, base=2)
            ),
            "counts": _time(
                lambda: entropy(counts, mode=InputMode.COUNTS, base=2)
            ),
            "probs": _time(
                lambda: entropy(probs, mode=InputMode.PROBS, base=2)
            ),
        }

        if HAS_CUPY:
            rows["gpu"] = _time(
                lambda: entropy(data, mode=InputMode.LABELS, base=2, use_gpu=True)
            )

        results[size] = rows  # type: ignore[assignment]

    return pd.DataFrame(results)


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------


def plot_results(df: pd.DataFrame) -> None:
    """Bar chart of benchmark results on a log scale."""
    fig, ax = plt.subplots(figsize=(10, 6))
    df.plot(kind="bar", ax=ax, logy=True, colormap="viridis")

    ax.set_title(
        "Entropy Benchmark — Runtime Scaling (log scale)",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_ylabel("Total runtime — 5 runs (seconds, lower is better)")
    ax.set_xlabel("Input mode")
    ax.tick_params(axis="x", rotation=0)
    ax.legend(title="Dataset size")

    fig.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    sample_labels = [1, 2, 2, 3, 3, 3]
    _, sample_counts = np.unique(sample_labels, return_counts=True)
    sample_probs = sample_counts / sample_counts.sum()

    print("=== Entropy examples (base-2, bits) ===")
    print(f"  From labels : {entropy(sample_labels, base=2):.6f}")
    print(f"  From counts : {entropy(sample_counts, mode=InputMode.COUNTS, base=2):.6f}")
    print(f"  From probs  : {entropy(sample_probs,  mode=InputMode.PROBS,  base=2):.6f}")

    if HAS_CUPY:
        print(
            f"  GPU (labels): "
            f"{entropy(sample_labels, base=2, use_gpu=True):.6f}"
        )

    print("\n=== Running benchmarks … ===")
    df_results = run_benchmarks()
    print(df_results.to_string())

    plot_results(df_results)


if __name__ == "__main__":
    main()
