import numpy as np

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
    # Case 3: raw labels given
    else:
        if labels.size <= 1:
            return 0.0
        _, counts = xp.unique(labels, return_counts=True)
        probs = counts / counts.sum()

    if probs.size <= 1:
        return 0.0

    log_fn = xp.log if base is None else (lambda x: xp.log(x) / xp.log(base))
    ent = -(probs * log_fn(probs)).sum()

    # Convert CuPy back to float if needed
    return float(ent.get() if use_gpu and HAS_CUPY else ent)


# -------------------------
# Example usage
# -------------------------
if __name__ == "__main__":
    labels = [1, 2, 2, 3, 3, 3]

    print("From raw labels:", entropy_np(labels, base=2))
    print("From counts:", entropy_np([1, 2, 3], from_counts=True, base=2))
    print("From probs:", entropy_np([0.1667, 0.3333, 0.5], from_probs=True, base=2))

    if HAS_CUPY:
        print("GPU accelerated:", entropy_np(labels, base=2, use_gpu=True))
