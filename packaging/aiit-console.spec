# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for aiit-console, the operator tool. See packaging/README.md.
#
#   pyinstaller --clean --noconfirm packaging/aiit-console.spec                      one-folder build: dist/aiit-console/
#   AIIT_PYI_ONEFILE=1 pyinstaller --clean --noconfirm packaging/aiit-console.spec   single file:      dist/aiit-console[.exe]
#
# The entry script imports the *installed* aiit package, so install it first
# (`pip install ".[release]"` or the wheel plus pyinstaller). The frozen program sets
# sys.frozen = True. The `anthropic` extra is not frozen in: a binary console has the
# dryrun and ollama providers; the anthropic provider needs a wheel install.
import os

from PyInstaller.utils.hooks import collect_submodules

NAME = "aiit-console"
ONEFILE = os.environ.get("AIIT_PYI_ONEFILE", "0") == "1"

a = Analysis(
    [os.path.join(SPECPATH, "entry_console.py")],
    pathex=[],
    binaries=[],
    datas=[],
    # Providers are imported lazily in aiit.console.llm.get_provider. PyInstaller's analysis
    # finds function-level imports too, but listing every submodule of the packages the
    # console uses costs nothing and survives a refactor to importlib.
    hiddenimports=collect_submodules("aiit.console") + collect_submodules("aiit.common"),
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
