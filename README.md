# Web-based attack detection on CIC-IDS2017

An ML pipeline that detects web-based attacks (Brute Force, XSS, SQL Injection)
in CIC-IDS2017 network flows. It loads the labeled flow CSV, cleans it, runs a
short feature analysis, trains baseline classifiers, and evaluates them with
imbalance-aware metrics.

The headline results in `report.md` were produced on the real file
`Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`.

## Layout

```
src/
  schema.py             canonical 78-feature schema and label helpers
  data.py               loading + cleaning (handles the empty-row artifact)
  features.py           variance / correlation / mutual-information analysis
  train.py              train + evaluate, writes metrics.json and plots
  generate_synthetic.py optional offline stand-in (not real data)
tests/
  test_pipeline.py      invariant tests (run on a tiny synthetic sample)
data/                   put the CIC-IDS2017 CSV here
outputs/                metrics.json and figures, per task
```

## Setup

With uv (recommended):

```bash
uv sync                 # runtime dependencies
uv sync --extra dev     # adds pytest, needed for `make test`
```

Or: `uv pip install -r requirements.txt`.

With plain pip:

```bash
pip install -r requirements.txt
```

## Get the data

Download `MachineLearningCSV.zip` (or the TrafficLabelling CSVs) from the
official source, https://www.unb.ca/cic/datasets/ids-2017.html, and place
`Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` in `data/`. The loader
picks up any `.csv` in `data/` other than the synthetic stand-in, so other
day-files (for example the Friday DDoS capture) work unchanged.

No download handy? Generate the offline stand-in instead:

```bash
make synthetic     # writes data/synthetic_web_attacks.csv
```

## Run

```bash
make run             # binary: benign vs web attack  -> outputs/binary/
make run-multiclass  # separates Brute Force / XSS / SQL Injection -> outputs/multiclass/
make test            # invariant tests
```

Direct invocation with options:

```bash
uv run python src/train.py --task binary --model random_forest \
  --test-size 0.3 --outdir outputs/binary
```

`--path FILE` points at a specific CSV. `--model` is `all`,
`logistic_regression`, or `random_forest`.

## Outputs

Each run writes to its `--outdir`:

- `metrics.json`: class distribution, feature analysis, and per-model metrics
  (accuracy, macro/weighted F1, per-class precision/recall/F1, confusion
  matrix, and for the binary task ROC-AUC and PR-AUC).
- `confusion_<model>.png`, `curves_<model>.png` (binary ROC + PR),
  `feature_importance.png` (RF importance and mutual information).

## Report

The write-up is `report.md`, with a typeset version in `report.pdf` (three
pages). Both carry the same content and the same numbers.

## Notes on the real file

- The TrafficLabelling CSVs ship with about 288k fully empty rows. The loader
  drops them automatically because their features coerce to all-NaN.
- The rate columns (`Flow Bytes/s`, `Flow Packets/s`) contain infinities; these
  are replaced and the affected rows dropped.
- Identifier columns (`Flow ID`, `Source IP`, `Timestamp`, ...) are ignored by
  name so they cannot leak into the model.

## Tools and assistance

See the final section of `report.md` for the full disclosure of libraries,
online resources, and AI assistant usage.
