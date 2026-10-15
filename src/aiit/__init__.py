"""AI_IT: open source, HIPAA-minded AI IT support for connected and offline endpoints."""

# The one place the version is written. setuptools reads it at build time
# ([tool.setuptools.dynamic] in pyproject.toml) and the release workflow refuses a
# tag that does not match it. PEP 440 spelling: "0.2.0", "0.2.0rc1"; the matching
# git tags are v0.2.0 and v0.2.0-rc1 (docs/release-process.md).
__version__ = "0.1.0"
