"""CyberSentinel detection-performance evaluation (spec parts 29-31).

Pure-Python (no scikit-learn dependency): confusion matrix, precision, recall,
specificity, F1, ROC-AUC from continuous scores, FPR/FNR, threshold sweep, and
latency statistics - plus a per-sample export for external plotting.
"""

from .metrics import (
    BinaryEvaluation,
    LatencyStats,
    EvaluationRun,
    confusion_counts,
    evaluate_binary,
    sweep_thresholds,
    best_threshold,
    roc_curve,
    roc_auc,
    latency_stats,
)

__all__ = [
    "BinaryEvaluation",
    "LatencyStats",
    "EvaluationRun",
    "confusion_counts",
    "evaluate_binary",
    "sweep_thresholds",
    "best_threshold",
    "roc_curve",
    "roc_auc",
    "latency_stats",
]
