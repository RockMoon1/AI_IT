# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for aiit-agent, the endpoint tool. See packaging/README.md.
#
#   pyinstaller --clean --noconfirm packaging/aiit-agent.spec                        one-folder build: dist/aiit-agent/
#   AIIT_PYI_ONEFILE=1 pyinstaller --clean --noconfirm packaging/aiit-agent.spec     single file:      dist/aiit-agent[.exe]
#
# The entry script imports the *installed* aiit package, so install it first
# (`pip install ".[release]"` or the wheel plus pyinstaller). The frozen program sets
# sys.frozen = True; the console script and the binary run the same aiit.agent.cli.main.
import os

from PyInstaller.utils.hooks import collect_submodules

NAME = "aiit-agent"
ONEFILE = os.environ.get("AIIT_PYI_ONEFILE", "0") == "1"

a = Analysis(
    [os.path.join(SPECPATH, "entry_agent.py")],
    pathex=[],
    binaries=[],
    datas=[],
    # Collectors and helpers are imported lazily inside functions. PyInstaller's analysis
    # finds those too, but listing every submodule of the packages the agent uses costs
    # nothing and survives a refactor to importlib. The console package is left out on purpose.
    hiddenimports=collect_submodules("aiit.agent") + collect_submodules("aiit.common"),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "_tkinter"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

if ONEFILE:
    EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,  # unsigned for now: docs/release-process.md, "Unsigned binaries"
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=NAME,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=True,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, upx_exclude=[], name=NAME)
