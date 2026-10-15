#!/usr/bin/env python3
"""PyInstaller entry point for ``aiit-console``, the operator tool.

This is the frozen-build twin of the ``aiit-console`` console script that pip installs
(``[project.scripts]`` in pyproject.toml): it calls ``aiit.console.cli.main`` and nothing
else, so a standalone binary and a wheel install behave identically. Keep it this thin;
behaviour belongs in the package, where the tests are.

Frozen builds are recognisable at runtime: PyInstaller sets ``sys.frozen = True`` and
``sys._MEIPASS`` (the directory the bundled files are unpacked to). A frozen console has
no ``pip``, so the ``anthropic`` extra cannot be added to it: the ``dryrun`` and ``ollama``
providers work, ``anthropic`` needs a wheel install. Built by packaging/aiit-console.spec.
"""
from aiit.console.cli import main

if __name__ == "__main__":
    main()
