# Use uv for environment management; falls back to plain python if uv is absent.
PY := uv run python
PYTEST := uv run pytest

.PHONY: help setup synthetic run run-multiclass test pdf clean

help:
	@echo "Targets:"
	@echo "  setup          install dependencies with uv"
	@echo "  synthetic      generate the synthetic stand-in dataset"
	@echo "  run            train + evaluate (binary) on data/ (real or synthetic)"
	@echo "  run-multiclass train + evaluate with the three attack subclasses"
	@echo "  test           run invariant tests"
	@echo "  pdf            render report.md to report.pdf"
	@echo "  clean          remove generated outputs and synthetic data"

setup:
	uv sync || uv pip install -r requirements.txt

synthetic:
	$(PY) src/generate_synthetic.py --out data/synthetic_web_attacks.csv

run:
	$(PY) src/train.py --data-dir data --task binary --outdir outputs/binary

run-multiclass:
	$(PY) src/train.py --data-dir data --task multiclass --outdir outputs/multiclass

test:
	$(PYTEST) -q

pdf:
	uv run --with markdown --with weasyprint python scripts/make_pdf.py

clean:
	rm -rf outputs/binary outputs/multiclass data/synthetic_web_attacks.csv
