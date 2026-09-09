"""Binary detection metrics + ROC-AUC + latency stats (pure Python).

Nothing here is hard-coded (spec part 37): every number is computed from the
(label, score/prediction) rows you pass in.

Convention: label / prediction 1 = THREAT (positive), 0 = BENIGN (negative).
`score` is a continuous risk score in [0, 1] or [0, 100] - ROC-AUC uses the
continuous score, never the thresholded label (spec part 30).
"""

from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass
class BinaryEvaluation:
    threshold: float
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: float
    precision: float
    recall: float            # sensitivity / TPR
    specificity: float       # TNR
    f1: float
    fpr: float
    fnr: float
    roc_auc: Optional[float]
    n: int
    positives: int
    negatives: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LatencyStats:
    count: int
    mean_ms: float
    median_ms: float
    min_ms: float
    max_ms: float
    p90_ms: float
    p95_ms: float
    p99_ms: float
    stdev_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _norm_score(value: float) -> float:
    v = float(value)
    if v > 1.0:               # accept 0-100 percentages
        v = v / 100.0
    return max(0.0, min(1.0, v))


def confusion_counts(
    labels: Sequence[int],
    predictions: Sequence[int],
) -> Tuple[int, int, int, int]:
    """Return (tp, tn, fp, fn)."""
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must be the same length")
    tp = tn = fp = fn = 0
    for y, p in zip(labels, predictions):
        y, p = int(bool(y)), int(bool(p))
        if y == 1 and p == 1:
            tp += 1
        elif y == 0 and p == 0:
            tn += 1
        elif y == 0 and p == 1:
            fp += 1
        else:
            fn += 1
    return tp, tn, fp, fn


def _safe_div(num: float, den: float) -> float:
    return num / den if den else 0.0


def roc_curve(labels: Sequence[int], scores: Sequence[float]) -> List[Tuple[float, float, float]]:
    """Return a list of (fpr, tpr, threshold) points, ordered by decreasing threshold.

    Uses the standard rank-sweep over the distinct scores.
    """
    if len(labels) != len(scores):
        raise ValueError("labels and scores must be the same length")
    rows = sorted(
        ((_norm_score(s), int(bool(y))) for s, y in zip(scores, labels)),
        key=lambda r: r[0],
        reverse=True,
    )
    total_pos = sum(y for _, y in rows)
    total_neg = len(rows) - total_pos
    if total_pos == 0 or total_neg == 0:
        return []

    points: List[Tuple[float, float, float]] = [(0.0, 0.0, math.inf)]
    tp = fp = 0
    i = 0
    n = len(rows)
    while i < n:
        thr = rows[i][0]
        # consume all rows at this exact score (ties)
        while i < n and rows[i][0] == thr:
            if rows[i][1] == 1:
                tp += 1
            else:
                fp += 1
            i += 1
        points.append((fp / total_neg, tp / total_pos, thr))
    return points


def roc_auc(labels: Sequence[int], scores: Sequence[float]) -> Optional[float]:
    """AUC via the Mann-Whitney U statistic (handles ties with 0.5 credit)."""
    pos = [_norm_score(s) for s, y in zip(scores, labels) if int(bool(y)) == 1]
    neg = [_norm_score(s) for s, y in zip(scores, labels) if int(bool(y)) == 0]
    if not pos or not neg:
        return None
    # rank-based computation
    all_scores = sorted((s, 0) for s in neg)
    all_scores += sorted((s, 1) for s in pos)
    all_scores.sort()
    # assign average ranks
    ranks = [0.0] * len(all_scores)
    i = 0
    while i < len(all_scores):
        j = i
        while j < len(all_scores) and all_scores[j][0] == all_scores[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j
    sum_ranks_pos = sum(r for r, (_, lab) in zip(ranks, all_scores) if lab == 1)
    n_pos, n_neg = len(pos), len(neg)
    u = sum_ranks_pos - n_pos * (n_pos + 1) / 2.0
    return u / (n_pos * n_neg)


def evaluate_binary(
    labels: Sequence[int],
    scores: Sequence[float],
    threshold: float = 0.5,
    predictions: Optional[Sequence[int]] = None,
) -> BinaryEvaluation:
    """Full metric set at one operating threshold.

    `scores` (continuous) drives ROC-AUC; `predictions` (if given) is used for
    the confusion matrix, else it is derived as score >= threshold.
    """
    thr = _norm_score(threshold) if threshold > 1.0 else float(threshold)
    norm_scores = [_norm_score(s) for s in scores]
    if predictions is None:
        predictions = [1 if s >= thr else 0 for s in norm_scores]

    tp, tn, fp, fn = confusion_counts(labels, predictions)
    n = tp + tn + fp + fn
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    return BinaryEvaluation(
        threshold=round(thr, 4),
        tp=tp, tn=tn, fp=fp, fn=fn,
        accuracy=round(_safe_div(tp + tn, n), 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        specificity=round(specificity, 4),
        f1=round(f1, 4),
        fpr=round(_safe_div(fp, fp + tn), 4),
        fnr=round(_safe_div(fn, fn + tp), 4),
        roc_auc=(round(v, 4) if (v := roc_auc(labels, norm_scores)) is not None else None),
        n=n,
        positives=tp + fn,
        negatives=tn + fp,
    )


def sweep_thresholds(
    labels: Sequence[int],
    scores: Sequence[float],
    thresholds: Iterable[float] = (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9),
) -> List[BinaryEvaluation]:
    """Evaluate at each threshold (spec part 11)."""
    return [evaluate_binary(labels, scores, t) for t in thresholds]


def best_threshold(
    labels: Sequence[int],
    scores: Sequence[float],
    thresholds: Iterable[float] = tuple(i / 100 for i in range(5, 100, 5)),
    objective: str = "f1",
) -> Tuple[float, BinaryEvaluation]:
    """Pick the threshold maximising an objective on the given data.

    objective: "f1" | "recall_at_precision" (>=0.9) | "youden" (recall+specificity-1)
    Report the selected threshold explicitly (spec part 11).
    """
    best: Optional[Tuple[float, BinaryEvaluation, float]] = None
    for t in thresholds:
        ev = evaluate_binary(labels, scores, t)
        if objective == "youden":
            key = ev.recall + ev.specificity - 1.0
        elif objective == "recall_at_precision":
            key = ev.recall if ev.precision >= 0.9 else -1.0
        else:
            key = ev.f1
        if best is None or key > best[2]:
            best = (t, ev, key)
    assert best is not None
    return best[0], best[1]


def latency_stats(latencies_ms: Sequence[float]) -> LatencyStats:
    vals = sorted(float(x) for x in latencies_ms if x is not None)
    if not vals:
        return LatencyStats(0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    def pct(p: float) -> float:
        if len(vals) == 1:
            return vals[0]
        idx = p / 100.0 * (len(vals) - 1)
        lo, hi = math.floor(idx), math.ceil(idx)
        return vals[lo] + (vals[hi] - vals[lo]) * (idx - lo)

    return LatencyStats(
        count=len(vals),
        mean_ms=round(statistics.fmean(vals), 2),
        median_ms=round(statistics.median(vals), 2),
        min_ms=round(vals[0], 2),
        max_ms=round(vals[-1], 2),
        p90_ms=round(pct(90), 2),
        p95_ms=round(pct(95), 2),
        p99_ms=round(pct(99), 2),
        stdev_ms=round(statistics.pstdev(vals), 2),
    )


@dataclass
class EvaluationRun:
    """A full evaluation over a labelled sample set + its per-sample export."""

    samples: List[Dict[str, Any]] = field(default_factory=list)   # {sample, label, score, prediction, latency_ms}

    def add(self, sample: str, label: int, score: float, prediction: Optional[int] = None,
            latency_ms: Optional[float] = None) -> None:
        s = _norm_score(score)
        self.samples.append({
            "sample": sample,
            "label": int(bool(label)),
            "score": round(s, 6),
            "prediction": int(bool(prediction)) if prediction is not None else (1 if s >= 0.5 else 0),
            "latency_ms": None if latency_ms is None else round(float(latency_ms), 2),
        })

    def summary(self, threshold: float = 0.5) -> Dict[str, Any]:
        if not self.samples:
            return {"error": "no samples"}
        labels = [r["label"] for r in self.samples]
        scores = [r["score"] for r in self.samples]
        lat = [r["latency_ms"] for r in self.samples if r["latency_ms"] is not None]
        return {
            "at_threshold": evaluate_binary(labels, scores, threshold).to_dict(),
            "threshold_sweep": [e.to_dict() for e in sweep_thresholds(labels, scores)],
            "roc_curve": [
                {"fpr": round(f, 4), "tpr": round(t, 4), "threshold": (None if math.isinf(th) else round(th, 4))}
                for f, t, th in roc_curve(labels, scores)
            ],
            "latency": latency_stats(lat).to_dict() if lat else None,
            "n_samples": len(self.samples),
        }

    def export(self, path: str | Path) -> Path:
        """Write per-sample rows (spec part 30) as JSON for external plotting."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "samples": self.samples,
            "summary": self.summary(),
        }, indent=2), encoding="utf-8")
        return p
