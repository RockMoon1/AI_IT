#!/usr/bin/env python3
"""PyInstaller entry point for ``aiit-agent``, the endpoint tool.

This is the frozen-build twin of the ``aiit-agent`` console script that pip installs
(``[project.scripts]`` in pyproject.toml): it calls ``aiit.agent.cli.main`` and nothing
else, so a standalone binary and a wheel install behave identically. Keep it this thin;
behaviour belongs in the package, where the tests are.

Frozen builds are recognisable at runtime: PyInstaller sets ``sys.frozen = True`` and
``sys._MEIPASS`` (the directory the bundled files are unpacked to). That flag is how the
agent tells a frozen build from a wheel install when it fills in ``aiit_frozen`` in a
bundle manifest; nothing else in aiit depends on it. Built by packaging/aiit-agent.spec.
"""
from aiit.agent.cli import main

if __name__ == "__main__":
    main()
