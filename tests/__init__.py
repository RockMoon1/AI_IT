"""Test package: importing it puts src/ on sys.path and scrubs the environment (see helpers)."""
from . import helpers  # noqa: F401
