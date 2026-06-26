"""Load and clean the CIC-IDS2017 web-attacks flows.

`load_dataset` accepts either the real CSV or the synthetic stand-in. The same
cleaning path runs for both: normalise column names, coerce features to numeric,
replace the infinities CICFlowMeter emits in the rate columns, drop unusable
rows and exact duplicates, and build both a binary and a multiclass target.
"""
from __future__ import annotations

import glob
import os
from dataclasses import dataclass

import numpy as np
import pandas as pd

from schema import (
    BENIGN_LABEL,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    normalise_label,
)

SYNTHETIC_FILE = "synthetic_web_attacks.csv"


@dataclass
class Dataset:
    X: pd.DataFrame          # numeric feature matrix
    y_binary: np.ndarray     # 0 = benign, 1 = web attack
    y_multi: pd.Series       # normalised class label
    feature_names: list[str]
    source_path: str
    is_synthetic: bool


def find_data_file(data_dir: str = "data") -> tuple[str, bool]:
    """Prefer any real CIC-IDS2017 CSV; fall back to the synthetic stand-in.

    Any .csv in the directory other than the synthetic file is treated as real
    data, so dropping in the Thursday web-attacks file or any other day-file
    just works.
    """
    real = sorted(
        p for p in glob.glob(os.path.join(data_dir, "*.csv"))
        if os.path.basename(p) != SYNTHETIC_FILE
    )
    if real:
        return real[0], False
    synthetic = os.path.join(data_dir, SYNTHETIC_FILE)
    if os.path.exists(synthetic):
        return synthetic, True
    raise FileNotFoundError(
        "No data found. Place a CIC-IDS2017 CSV (for the project, "
        "'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv') in "
        f"'{data_dir}/', or run 'make synthetic' to create the stand-in."
    )


def _read_csv(path: str) -> pd.DataFrame:
    # The real file uses latin-1 because of the en-dash in the attack labels.
    for enc in ("utf-8", "latin-1"):
        try:
            return pd.read_csv(path, encoding=enc, low_memory=False)
        except UnicodeDecodeError:
            continue
    return pd.read_csv(path, encoding="latin-1", low_memory=False, engine="python")


def load_dataset(data_dir: str = "data", path: str | None = None) -> Dataset:
    if path is None:
        path, is_synth = find_data_file(data_dir)
    else:
        is_synth = SYNTHETIC_FILE in os.path.basename(path)

    df = _read_csv(path)
    df.columns = [c.strip() for c in df.columns]

    if LABEL_COLUMN not in df.columns:
        raise ValueError(f"Expected a '{LABEL_COLUMN}' column in {path}.")

    present = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        # Tolerate minor schema drift between dataset releases.
        print(f"[load] note: {len(missing)} expected feature(s) absent, ignoring.")

    X = df[present].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)

    labels = df[LABEL_COLUMN].map(normalise_label)

    # Drop rows with any non-finite feature, and exact duplicate flows.
    keep = X.notna().all(axis=1)
    X, labels = X[keep], labels[keep]
    dup = X.duplicated(keep="first")
    X, labels = X[~dup].reset_index(drop=True), labels[~dup].reset_index(drop=True)

    # Drop constant columns (several bulk-rate features are all zero).
    nunique = X.nunique()
    constant = nunique[nunique <= 1].index.tolist()
    if constant:
        X = X.drop(columns=constant)

    # Binary target: benign vs attack, where attack is any non-benign label.
    # This keeps the pipeline file-agnostic (web attacks, DDoS, port scan, ...).
    y_binary = (labels != BENIGN_LABEL).astype(int).to_numpy()
    y_multi = labels.copy()

    return Dataset(
        X=X,
        y_binary=y_binary,
        y_multi=y_multi,
        feature_names=list(X.columns),
        source_path=path,
        is_synthetic=is_synth,
    )


def class_distribution(ds: Dataset) -> pd.Series:
    return ds.y_multi.value_counts()
