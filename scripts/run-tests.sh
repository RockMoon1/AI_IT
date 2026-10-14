#!/usr/bin/env sh
# Runs the unit tests without installing the package (uses src/ on PYTHONPATH).
# Usage: scripts/run-tests.sh [--coverage] [unittest args...]
cd "$(dirname "$0")/.." || exit 1
if [ "$1" = "--coverage" ]; then
  shift
  PYTHONPATH=src python3 -m coverage run -m unittest discover -s tests -t . -v "$@" && python3 -m coverage combine >/dev/null 2>&1; python3 -m coverage report
else
  PYTHONPATH=src python3 -m unittest discover -s tests -t . -v "$@"
fi
