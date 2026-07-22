"""Isolation Forest: trained with scikit-learn, scored in pure Python.

`train()` fits sklearn's IsolationForest on feature rows and exports every tree
to JSON. `Forest` loads that JSON and computes the same anomaly score sklearn's
`score_samples` would (tests/test_iforest.py checks agreement to 1e-9), so the
always-on service never imports numpy or scikit-learn and stays small.

Score s(x) is in (0, 1): about 0.5 or below is ordinary, close to 1 is easy to
isolate, i.e. unusual for this network.
"""
from __future__ import annotations

import json
import math
import os
import struct
import time

from .features import FEATURES

EULER = 0.5772156649015329
_F32 = struct.Struct("f")


def average_path_length(n: float) -> float:
    """c(n): average depth of an unsuccessful search in a binary search tree of n items."""
    if n <= 1:
        return 0.0
    if n <= 2:
        return 1.0
    return 2.0 * (math.log(n - 1.0) + EULER) - 2.0 * (n - 1.0) / n


def _f32(x: float) -> float:
    # sklearn's trees compare float32 copies of the input; do the same for exact parity
    return _F32.unpack(_F32.pack(x))[0]


class Forest:
    def __init__(self, model: dict):
        self.meta = {k: v for k, v in model.items() if k != "trees"}
        self.features: list[str] = model["features"]
        self.threshold: float = model["threshold"]
        self.median: list[float] = model["median"]
        self.spread: list[float] = model["spread"]
        self.trees = model["trees"]
        self.denominator = len(self.trees) * average_path_length(model["max_samples"])
        # leaf contribution = path length so far + c(samples left in the leaf) - 1
        for t in self.trees:
            t["leaf_extra"] = [average_path_length(n) - 1.0 for n in t["n"]]

    @classmethod
    def load(cls, path: str) -> "Forest":
        with open(path) as f:
            return cls(json.load(f))

    def score(self, x: list[float]) -> float:
        xf = [_f32(v) for v in x]
        total = 0.0
        for t in self.trees:
            left, right, feat, thr = t["left"], t["right"], t["feature"], t["threshold"]
            cols = t["features"]
            node, depth = 0, 1
            while left[node] != -1:
                node = left[node] if xf[cols[feat[node]]] <= thr[node] else right[node]
                depth += 1
            total += depth + t["leaf_extra"][node]
        return 2.0 ** (-total / self.denominator)

    def explain(self, x: list[float], top: int = 2) -> list[str]:
        """The features furthest from this network's typical values, for alert text."""
        z = [((v - m) / s if s else 0.0, name)
             for v, m, s, name in zip(x, self.median, self.spread, self.features)]
        z.sort(key=lambda t: -abs(t[0]))
        return [f"{name} {'high' if d > 0 else 'low'}" for d, name in z[:top] if abs(d) >= 1.5]


# ------------------------------------------------------------------ training (needs sklearn)

def _export(model, X, threshold: float, n_rows: int, span: tuple[int, int]) -> dict:
    import numpy as np
    trees = []
    for est, cols in zip(model.estimators_, model.estimators_features_):
        tr = est.tree_
        trees.append({
            "features": [int(c) for c in cols],
            "left": tr.children_left.tolist(),
            "right": tr.children_right.tolist(),
            "feature": [int(f) if f >= 0 else 0 for f in tr.feature],
            "threshold": [float(t) for t in tr.threshold],
            "n": tr.n_node_samples.tolist(),
        })
    med = np.median(X, axis=0)
    q75, q25 = np.percentile(X, [75, 25], axis=0)
    spread = np.maximum(q75 - q25, 1e-3)
    return {
        "version": 1,
        "features": FEATURES,
        "max_samples": int(model.max_samples_),
        "threshold": threshold,
        "median": med.tolist(),
        "spread": spread.tolist(),
        "trained_rows": n_rows,
        "trained_span": list(span),
        "created": time.time(),
        "trees": trees,
    }


def train(rows: list, out_path: str, holdout: float = 0.3, fp_budget: float = 0.005,
          seed: int = 0) -> dict:
    """Fit on the earliest (1 - holdout) of rows (time order) and save the model.

    The alert threshold is the larger of sklearn's default (0.5) and the score
    that only `fp_budget` of training windows exceed, so ordinary traffic on
    *this* network almost never alerts.
    """
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:
        raise SystemExit("pktan train needs scikit-learn: sudo apt install python3-sklearn "
                         "(only training needs it; the service doesn't)") from None
    if len(rows) < 50:
        raise SystemExit(f"only {len(rows)} feature rows so far; let pktan run longer first")
    cut = max(1, int(len(rows) * (1 - holdout)))
    train_rows = rows[:cut]
    X = np.array([r[2] for r in train_rows], dtype=float)
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=seed).fit(X)
    train_scores = -model.score_samples(X)
    threshold = float(max(0.5, np.quantile(train_scores, 1 - fp_budget)))
    data = _export(model, X, threshold, len(train_rows), (train_rows[0][0], train_rows[-1][0]))
    tmp = out_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(tmp, out_path)
    return {"model": model, "train": train_rows, "holdout": rows[cut:], "threshold": threshold}


# ------------------------------------------------------------------ evaluation

# A typical fixed-threshold detector: flag a device-minute if any count is over a
# static limit. These are the limits pktan's comparison uses; they're reasonable
# guesses, not tuned to this network, which is exactly their weakness.
FIXED_LIMITS = {"pkts_out": 500, "bytes_out": 1_000_000, "dst_ips": 30, "dst_ports": 20,
                "syn_out": 20, "rst_in": 10, "dns_queries": 30}


def fixed_threshold_flags(vec: list[float]) -> list[str]:
    raw = {name: math.expm1(v) for name, v in zip(FEATURES, vec)}
    return [k for k, limit in FIXED_LIMITS.items() if raw[k] > limit]


def evaluate(forest: Forest, holdout: list, attacks: list | None = None) -> dict:
    """Compare fixed thresholds and the forest on held-out normal rows (+ attack rows)."""
    res = {"holdout_rows": len(holdout)}
    fixed = sum(1 for _, _, v in holdout if fixed_threshold_flags(v))
    forest_hits = sum(1 for _, _, v in holdout if forest.score(v) > forest.threshold)
    res["fixed_flagged"], res["forest_flagged"] = fixed, forest_hits
    if attacks:
        res["attacks"] = [{"name": name, "fixed": bool(fixed_threshold_flags(v)),
                           "forest": forest.score(v) > forest.threshold,
                           "score": round(forest.score(v), 3)} for name, v in attacks]
    return res
