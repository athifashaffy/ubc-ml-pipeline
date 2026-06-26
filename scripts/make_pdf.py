"""Render report.md to a print-ready report.pdf.

Markdown -> HTML -> PDF via WeasyPrint, which renders CSS tables faithfully.

    uv run --with markdown --with weasyprint python scripts/make_pdf.py

WeasyPrint needs the native cairo/pango libraries. On macOS install them with
`brew install pango` (pulls cairo too); this script locates them automatically
via `brew --prefix`. On Debian/Ubuntu: `apt-get install libpango-1.0-0
libpangocairo-1.0-0`. Flags: --in FILE (default report.md), --out FILE
(default report.pdf). The CSS is tuned to keep the report within three pages.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def _ensure_native_libs() -> None:
    """Point the dynamic loader at Homebrew's cairo/pango before importing
    WeasyPrint, so the C extensions resolve on macOS."""
    if sys.platform != "darwin":
        return
    try:
        prefix = subprocess.check_output(
            ["brew", "--prefix"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return
    libdir = os.path.join(prefix, "lib")
    existing = os.environ.get("DYLD_FALLBACK_LIBRARY_PATH", "")
    os.environ["DYLD_FALLBACK_LIBRARY_PATH"] = (
        f"{libdir}:{existing}" if existing else libdir
    )


# Compact print styling so the report stays within three pages.
CSS = """
@page { size: A4 portrait; margin: 1.4cm 1.6cm; }
body { font-family: Helvetica, Arial, sans-serif; font-size: 9pt; line-height: 1.32;
       color: #111; }
h1 { font-size: 15pt; margin: 0 0 6px 0; }
h2 { font-size: 11.5pt; margin: 10px 0 3px 0; border-bottom: 1px solid #999;
     padding-bottom: 2px; }
h3 { font-size: 10pt; margin: 8px 0 2px 0; }
p  { margin: 3px 0; }
table { border-collapse: collapse; width: 100%; margin: 4px 0 8px 0; font-size: 8.3pt; }
th, td { border: 1px solid #bbb; padding: 2px 5px; text-align: left; }
th { background: #eee; }
td:not(:first-child), th:not(:first-child) { text-align: right; }
code { font-family: monospace; font-size: 8.3pt; }
"""


def build(md_path: Path, pdf_path: Path) -> None:
    import markdown
    from weasyprint import HTML

    text = md_path.read_text(encoding="utf-8")
    body = markdown.markdown(text, extensions=["tables", "fenced_code"])
    html = f"<html><head><style>{CSS}</style></head><body>{body}</body></html>"
    HTML(string=html).write_pdf(pdf_path)
    print(f"[done] {md_path} -> {pdf_path} ({pdf_path.stat().st_size/1024:.0f} KB)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Render report.md to report.pdf")
    ap.add_argument("--in", dest="src", default="report.md")
    ap.add_argument("--out", dest="dst", default="report.pdf")
    args = ap.parse_args()
    _ensure_native_libs()
    build(Path(args.src), Path(args.dst))


if __name__ == "__main__":
    main()
