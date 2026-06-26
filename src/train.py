"""Train and evaluate baseline web-attack detectors on CIC-IDS2017 flows.

Pipeline: load -> clean -> feature analysis -> stratified split -> train
baseline(s) -> evaluate with imbalance-aware metrics -> write metrics.json and
plots to the output directory.

Primary task is binary (benign vs web attack), which is what "attack detection"
asks for. Pass --task multiclass to separate Brute Force / XSS / Sql Injection.
"""
from __future__ import annotations

import argparse
import json
import os
import warnings

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    auc,
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import data as data_mod
import features as feat_mod

warnings.filterwarnings("ignore", category=UserWarning)


def build_models(task: str) -> dict[str, Pipeline]:
    rf_weight = "balanced_subsample"
    lr_weight = "balanced"
    return {
        "logistic_regression": Pipeline([
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=2000, class_weight=lr_weight, n_jobs=-1)),
        ]),
        "random_forest": Pipeline([
            ("clf", RandomForestClassifier(
                n_estimators=200, max_depth=None, n_jobs=-1,
                class_weight=rf_weight, random_state=42)),
        ]),
    }


def evaluate(name, model, X_test, y_test, labels, task, outdir):
    y_pred = model.predict(X_test)
    report = classification_report(
        y_test, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    metrics = {
        "model": name,
        "task": task,
        "accuracy": float(report["accuracy"]),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "per_class": {
            str(k): v for k, v in report.items()
            if k not in ("accuracy", "macro avg", "weighted avg")
        },
        "confusion_matrix": cm.tolist(),
        "confusion_labels": [str(c) for c in labels],
    }

    if task == "binary" and hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_test)[:, 1]
        metrics["roc_auc"] = float(roc_auc_score(y_test, proba))
        metrics["pr_auc"] = float(average_precision_score(y_test, proba))
        _plot_curves(name, y_test, proba, outdir)

    _plot_confusion(name, cm, labels, outdir)
    return metrics


def _plot_confusion(name, cm, labels, outdir):
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay(cm, display_labels=labels).plot(
        ax=ax, cmap="Blues", colorbar=False, xticks_rotation=45)
    ax.set_title(f"Confusion matrix: {name}")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, f"confusion_{name}.png"), dpi=130)
    plt.close(fig)


def _plot_curves(name, y_test, proba, outdir):
    fpr, tpr, _ = roc_curve(y_test, proba)
    prec, rec, _ = precision_recall_curve(y_test, proba)
    fig, axes = plt.subplots(1, 2, figsize=(9, 4))
    axes[0].plot(fpr, tpr, label=f"AUC={auc(fpr, tpr):.3f}")
    axes[0].plot([0, 1], [0, 1], "k--", lw=0.8)
    axes[0].set(xlabel="False positive rate", ylabel="True positive rate",
                title=f"ROC: {name}")
    axes[0].legend(loc="lower right")
    axes[1].plot(rec, prec, label=f"AP={average_precision_score(y_test, proba):.3f}")
    axes[1].set(xlabel="Recall", ylabel="Precision", title=f"PR: {name}")
    axes[1].legend(loc="lower left")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, f"curves_{name}.png"), dpi=130)
    plt.close(fig)


def _plot_importance(model, feature_names, outdir, mi: pd.Series):
    rf = model.named_steps.get("clf")
    if not hasattr(rf, "feature_importances_"):
        return
    imp = pd.Series(rf.feature_importances_, index=feature_names)
    top = imp.sort_values(ascending=False).head(15)[::-1]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    top.plot.barh(ax=axes[0], color="#3b6ea5")
    axes[0].set_title("Random forest importance (top 15)")
    mi.head(15)[::-1].plot.barh(ax=axes[1], color="#5a9367")
    axes[1].set_title("Mutual information (top 15)")
    fig.tight_layout()
    fig.savefig(os.path.join(outdir, "feature_importance.png"), dpi=130)
    plt.close(fig)


def run(args) -> None:
    os.makedirs(args.outdir, exist_ok=True)
    ds = data_mod.load_dataset(args.data_dir, path=args.path)

    print(f"[data] source: {ds.source_path}  synthetic={ds.is_synthetic}")
    dist = data_mod.class_distribution(ds)
    print("[data] class distribution:")
    print(dist.to_string())
    print(f"[data] rows={len(ds.X):,}  features={len(ds.feature_names)}")

    # Feature analysis (reported, not destructive beyond the loader's own pruning).
    lowvar = feat_mod.low_variance_columns(ds.X)
    corr_pairs = feat_mod.correlated_pairs(ds.X)
    mi = feat_mod.mutual_information(ds.X, ds.y_binary)
    print(f"[features] near-zero-variance: {len(lowvar)} | "
          f"correlated pairs >=0.95: {len(corr_pairs)}")
    print("[features] top 8 by mutual information:")
    print(mi.head(8).round(4).to_string())

    y = ds.y_binary if args.task == "binary" else ds.y_multi.to_numpy()
    labels = [0, 1] if args.task == "binary" else sorted(pd.unique(y).tolist())
    label_names = (["benign", "attack"] if args.task == "binary" else labels)

    X_train, X_test, y_train, y_test = train_test_split(
        ds.X, y, test_size=args.test_size, stratify=y, random_state=42)
    print(f"[split] train={len(X_train):,}  test={len(X_test):,}")

    models = build_models(args.task)
    if args.model != "all":
        models = {args.model: models[args.model]}

    all_metrics = []
    for name, model in models.items():
        print(f"\n[train] {name} ...")
        model.fit(X_train, y_train)
        m = evaluate(name, model, X_test, y_test, label_names, args.task, args.outdir)
        all_metrics.append(m)
        line = f"[result] {name}: acc={m['accuracy']:.4f} macroF1={m['macro_f1']:.4f}"
        if "roc_auc" in m:
            line += f" rocAUC={m['roc_auc']:.4f} prAUC={m['pr_auc']:.4f}"
        print(line)
        if name == "random_forest":
            _plot_importance(model, ds.feature_names, args.outdir, mi)

    summary = {
        "source_path": ds.source_path,
        "is_synthetic": ds.is_synthetic,
        "task": args.task,
        "n_rows": int(len(ds.X)),
        "n_features": len(ds.feature_names),
        "class_distribution": {str(k): int(v) for k, v in dist.items()},
        "feature_analysis": {
            "near_zero_variance": lowvar,
            "n_correlated_pairs_ge_0p95": len(corr_pairs),
            "top_mutual_information": mi.head(10).round(5).to_dict(),
        },
        "models": all_metrics,
    }
    out_json = os.path.join(args.outdir, "metrics.json")
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[done] metrics -> {out_json}")
    print(f"[done] plots   -> {args.outdir}/")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--path", default=None, help="Explicit CSV path (overrides data-dir).")
    ap.add_argument("--task", choices=["binary", "multiclass"], default="binary")
    ap.add_argument("--model", choices=["all", "logistic_regression", "random_forest"],
                    default="all")
    ap.add_argument("--test-size", type=float, default=0.3)
    ap.add_argument("--outdir", default="outputs")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
