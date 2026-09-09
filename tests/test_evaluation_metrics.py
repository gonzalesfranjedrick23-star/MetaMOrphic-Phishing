"""Evaluation module (spec parts 29-31) - metrics computed, never hard-coded."""

import math

from cybersentinel.evaluation import (
    confusion_counts, evaluate_binary, sweep_thresholds, best_threshold,
    roc_auc, roc_curve, latency_stats, EvaluationRun,
)


def test_confusion_and_rates():
    labels = [1, 1, 1, 0, 0, 0, 0]
    preds = [1, 1, 0, 0, 0, 1, 0]
    tp, tn, fp, fn = confusion_counts(labels, preds)
    assert (tp, tn, fp, fn) == (2, 3, 1, 1)
    ev = evaluate_binary(labels, [0.9, 0.8, 0.4, 0.1, 0.2, 0.6, 0.3], predictions=preds)
    assert ev.precision == round(2 / 3, 4)
    assert ev.recall == round(2 / 3, 4)
    assert ev.specificity == 0.75
    assert ev.fpr == 0.25
    assert ev.fnr == round(1 / 3, 4)
    assert math.isclose(ev.f1, 2 * ev.precision * ev.recall / (ev.precision + ev.recall), abs_tol=1e-3)


def test_roc_auc_perfect_and_random():
    # perfectly separable -> AUC 1.0
    labels = [0, 0, 0, 1, 1, 1]
    scores = [0.1, 0.2, 0.3, 0.7, 0.8, 0.9]
    assert roc_auc(labels, scores) == 1.0
    # reversed -> AUC 0.0
    assert roc_auc(labels, scores[::-1]) == 0.0
    # ties at the boundary -> 0.5
    assert roc_auc([0, 1], [0.5, 0.5]) == 0.5


def test_roc_auc_uses_continuous_score_not_labels():
    # thresholded predictions identical, but scores differ -> AUC differs
    labels = [0, 0, 1, 1]
    good = [0.1, 0.2, 0.85, 0.95]
    weak = [0.45, 0.49, 0.51, 0.55]
    assert roc_auc(labels, good) == 1.0
    assert roc_auc(labels, weak) == 1.0  # still separable
    mixed = [0.2, 0.6, 0.4, 0.9]
    assert 0.0 < roc_auc(labels, mixed) < 1.0


def test_roc_curve_monotonic():
    labels = [0, 1, 0, 1, 0, 1, 1, 0]
    scores = [0.1, 0.9, 0.35, 0.8, 0.2, 0.6, 0.55, 0.4]
    pts = roc_curve(labels, scores)
    assert pts[0][:2] == (0.0, 0.0)
    assert pts[-1][:2] == (1.0, 1.0)
    fprs = [p[0] for p in pts]
    tprs = [p[1] for p in pts]
    assert fprs == sorted(fprs)
    assert tprs == sorted(tprs)


def test_threshold_sweep_and_selection():
    labels = [0] * 20 + [1] * 20
    scores = [0.05 * i for i in range(20)] + [0.4 + 0.03 * i for i in range(20)]
    sweep = sweep_thresholds(labels, scores)
    assert {e.threshold for e in sweep} == {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9}
    t, ev = best_threshold(labels, scores, objective="f1")
    assert 0.0 < t < 1.0
    assert ev.f1 >= max(e.f1 for e in sweep) - 0.15


def test_latency_percentiles():
    stats = latency_stats([10, 20, 30, 40, 50, 60, 70, 80, 90, 100])
    assert stats.count == 10
    assert stats.min_ms == 10 and stats.max_ms == 100
    assert stats.median_ms == 55
    assert stats.p90_ms >= stats.median_ms
    assert latency_stats([]).count == 0


def test_evaluation_run_export(tmp_path):
    run = EvaluationRun()
    for i in range(10):
        run.add(f"benign_{i}", label=0, score=0.05 * i, latency_ms=12 + i)
    for i in range(10):
        run.add(f"threat_{i}", label=1, score=0.6 + 0.03 * i, latency_ms=20 + i)
    out = run.export(tmp_path / "eval.json")
    assert out.exists()
    summary = run.summary()
    assert summary["n_samples"] == 20
    assert summary["at_threshold"]["roc_auc"] is not None
    assert summary["latency"]["count"] == 20
    assert len(summary["roc_curve"]) >= 2
