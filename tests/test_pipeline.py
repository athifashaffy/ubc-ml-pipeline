"""Invariant tests for the pipeline.

These run on a tiny synthetic sample so they are fast and need no download.
"""
import os
import sys

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import data as data_mod  # noqa: E402
import generate_synthetic as gen  # noqa: E402
from schema import FEATURE_COLUMNS, is_attack, normalise_label  # noqa: E402


@pytest.fixture(scope="module")
def tiny_csv(tmp_path_factory):
    d = tmp_path_factory.mktemp("data")
    path = d / "synthetic_web_attacks.csv"
    gen.generate(scale=0.02, seed=1).to_csv(path, index=False)
    return str(path)


def test_label_normalisation_handles_dash_variants():
    assert normalise_label("Web Attack \x96 XSS") == "Web Attack - XSS"
    assert normalise_label("Web Attack \u2013 Brute Force") == "Web Attack - Brute Force"


def test_is_attack_only_flags_web_attacks():
    assert is_attack("Web Attack - Sql Injection")
    assert not is_attack("BENIGN")


def test_loader_returns_finite_numeric_features(tiny_csv):
    ds = data_mod.load_dataset(path=tiny_csv)
    assert np.isfinite(ds.X.to_numpy()).all(), "features must be finite after cleaning"
    assert not ds.X.isna().any().any(), "no NaNs may survive cleaning"


def test_binary_target_is_zero_one(tiny_csv):
    ds = data_mod.load_dataset(path=tiny_csv)
    assert set(np.unique(ds.y_binary)).issubset({0, 1})
    assert ds.y_binary.sum() > 0 and ds.y_binary.sum() < len(ds.y_binary)


def test_no_duplicate_rows_after_cleaning(tiny_csv):
    ds = data_mod.load_dataset(path=tiny_csv)
    assert not ds.X.duplicated().any(), "duplicates must be dropped"


def test_feature_names_are_subset_of_schema(tiny_csv):
    ds = data_mod.load_dataset(path=tiny_csv)
    assert set(ds.feature_names).issubset(set(FEATURE_COLUMNS))
