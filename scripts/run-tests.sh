#!/usr/bin/env sh
# Runs the unit tests without installing the package (uses src/ on PYTHONPATH).
cd "$(dirname "$0")/.." || exit 1
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v "$@"
