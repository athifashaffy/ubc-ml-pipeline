"""Generate a synthetic stand-in for the CIC-IDS2017 web-attacks file.

This is an OPTIONAL offline fallback. The project runs on the real
`Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`; this generator only
exists so the pipeline and tests can run with no download available. It
reproduces the 79-column schema, the four real class labels, and the documented
severe class imbalance, with deliberately overlapping class-conditional features
so the minority classes stay hard.

Numbers produced from this file are illustrative only and are NOT real
CIC-IDS2017 results.
"""
from __future__ import annotations

import argparse

import numpy as np
import pandas as pd

from schema import FEATURE_COLUMNS, LABEL_COLUMN, REAL_CLASS_COUNTS

# A small subset of features carries most of the class signal in the real file
# (packet-length and flow-timing statistics). We give those shifted means per
# attack type and leave the rest as shared background noise.
SIGNAL_FEATURES = [
    "Total Fwd Packets", "Fwd Packet Length Mean", "Flow Bytes/s",
    "Average Packet Size", "Init_Win_bytes_forward",
]

# Per-class mean shift on the signal features, in units of the signal scale.
# Brute Force is the most separable, XSS is moderate, Sql Injection is faint
# and starved of samples so it is the hardest minority class. This reproduces
# the qualitative pattern seen on the real file: benign and brute force are
# detected well, XSS less so, and Sql Injection (21 flows) barely at all.
CLASS_SHIFT = {
    "BENIGN": 0.0,
    "Web Attack - Brute Force": 3.0,
    "Web Attack - XSS": 1.6,
    "Web Attack - Sql Injection": 1.1,
}

_SIG_LOC = 20.0   # benign mean on a signal feature
_SIG_GAP = 6.0    # raw shift per unit of CLASS_SHIFT
_SIG_SCALE = 9.0  # within-class spread (large enough that classes overlap)


def _block(rng: np.random.Generator, n: int, shift: float) -> np.ndarray:
    # Background flow-like magnitudes for every column (non-discriminative).
    out = rng.exponential(50.0, size=(n, len(FEATURE_COLUMNS)))
    out += rng.normal(0.0, 5.0, size=out.shape)
    # Replace the signal columns with a cleaner, class-shifted distribution so
    # the separability is controlled rather than swamped by background noise.
    sig_idx = [FEATURE_COLUMNS.index(f) for f in SIGNAL_FEATURES]
    for j in sig_idx:
        out[:, j] = rng.normal(_SIG_LOC + shift * _SIG_GAP, _SIG_SCALE, size=n)
    return np.abs(out)


def generate(scale: float = 1.0, seed: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    frames = []
    for label, real_n in REAL_CLASS_COUNTS.items():
        n = max(1, int(round(real_n * scale)))
        block = _block(rng, n, CLASS_SHIFT[label])
        df = pd.DataFrame(block, columns=FEATURE_COLUMNS)
        df[LABEL_COLUMN] = label
        frames.append(df)
    out = pd.concat(frames, ignore_index=True)
    # Inject the messiness the real file is known for: a few infinities and
    # NaNs in the rate columns, plus some duplicate rows.
    rate_cols = ["Flow Bytes/s", "Flow Packets/s"]
    inf_idx = rng.choice(out.index, size=max(1, len(out) // 5000), replace=False)
    out.loc[inf_idx, rate_cols[0]] = np.inf
    nan_idx = rng.choice(out.index, size=max(1, len(out) // 5000), replace=False)
    out.loc[nan_idx, rate_cols[1]] = np.nan
    dup = out.sample(n=max(1, len(out) // 200), random_state=seed)
    out = pd.concat([out, dup], ignore_index=True)
    return out.sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="data/synthetic_web_attacks.csv")
    ap.add_argument(
        "--scale", type=float, default=1.0,
        help="Fraction of real row counts to generate (1.0 = full size).",
    )
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    df = generate(scale=args.scale, seed=args.seed)
    df.to_csv(args.out, index=False)
    print(f"wrote {len(df):,} rows x {df.shape[1]} cols to {args.out}")
    print(df[LABEL_COLUMN].value_counts().to_string())


if __name__ == "__main__":
    main()
