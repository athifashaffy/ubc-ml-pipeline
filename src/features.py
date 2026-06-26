"""Lightweight feature analysis for the flow features.

Three cheap signals that are enough to justify a baseline feature set:
  - near-zero variance columns add nothing,
  - highly correlated pairs are redundant,
  - mutual information ranks what actually separates benign from attack.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.feature_selection import mutual_info_classif


def low_variance_columns(X: pd.DataFrame, threshold: float = 1e-8) -> list[str]:
    var = X.var(axis=0, numeric_only=True)
    return var[var <= threshold].index.tolist()


def correlated_pairs(X: pd.DataFrame, threshold: float = 0.95) -> list[tuple[str, str, float]]:
    corr = X.corr(numeric_only=True).abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    pairs = []
    for col in upper.columns:
        for row in upper.index:
            v = upper.loc[row, col]
            if pd.notna(v) and v >= threshold:
                pairs.append((row, col, float(v)))
    return sorted(pairs, key=lambda t: -t[2])


def mutual_information(X: pd.DataFrame, y: np.ndarray, sample: int = 50000,
                       seed: int = 0) -> pd.Series:
    if len(X) > sample:
        idx = np.random.default_rng(seed).choice(len(X), size=sample, replace=False)
        Xs, ys = X.iloc[idx], y[idx]
    else:
        Xs, ys = X, y
    mi = mutual_info_classif(Xs, ys, random_state=seed)
    return pd.Series(mi, index=X.columns).sort_values(ascending=False)
