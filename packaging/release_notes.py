#!/usr/bin/env python3
"""Release helpers for .github/workflows/release.yml. Standard library only, Python 3.10+.

    python packaging/release_notes.py version
        Print the package version, read from src/aiit/__init__.py without importing aiit.
    python packaging/release_notes.py check [--tag vX.Y.Z]
        Exit non-zero unless the tag (when given) names the same version as __version__ and
        CHANGELOG.md has a non-empty section for it. Prints `version=...`, `prerelease=true|false`
        and `notes_section=...` lines, ready for $GITHUB_OUTPUT.
    python packaging/release_notes.py section [--tag vX.Y.Z]
        Print the CHANGELOG section the release notes come from.
    python packaging/release_notes.py body --tag vX.Y.Z [--assets DIR]
        Print the GitHub Release body: the CHANGELOG section, the asset table, how to verify a
        download, the unsigned-binary notice and the install lines.

Tags are `vX.Y.Z` for releases and `vX.Y.Z-rcN` (or `-betaN`, `-alphaN`) for pre-releases;
__version__ holds the PEP 440 spelling (`X.Y.Z`, `X.Y.ZrcN`). A pre-release whose own CHANGELOG
section does not exist yet takes its notes from `[Unreleased]`.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = "RockMoon1/AI_IT"

_VERSION_RE = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>\d*))?"
    r"(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>\d*))?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d*))?$",
    re.IGNORECASE,
)
_PRE_ALIAS = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "pre": "rc", "preview": "rc", "rc": "rc"}
_LINK_REF_RE = re.compile(r"^\[[^\]]+\]:\s+https?://\S+\s*$")


def read_version(root: Path = ROOT) -> str:
    """The `__version__` string of src/aiit/__init__.py, read as text (no import, no dependencies)."""
    text = (root / "src" / "aiit" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    if not m:
        raise ValueError("src/aiit/__init__.py has no __version__ assignment")
    return m.group(1)


def normalize(version: str) -> str:
    """PEP 440 canonical form of a version or a v-prefixed tag: `v0.2.0-rc1` -> `0.2.0rc1`.

    Raises ValueError for anything that is not a release version (for example `Unreleased`).
    """
    m = _VERSION_RE.match(version.strip())
    if not m:
        raise ValueError(f"not a release version: {version!r}")
    out = ".".join(str(int(part)) for part in m.group("release").split("."))
    if m.group("pre_l") is not None:
        out += _PRE_ALIAS[m.group("pre_l").lower()] + (m.group("pre_n") or "0")
    if m.group("post_l") is not None:
        out += ".post" + (m.group("post_n") or "0")
    if m.group("dev_l") is not None:
        out += ".dev" + (m.group("dev_n") or "0")
    return out


def is_prerelease(version: str) -> bool:
    """True for alpha, beta, release-candidate and dev versions (marked pre-release on GitHub, published to TestPyPI)."""
    return re.search(r"(?:a|b|rc)\d+|\.dev\d+", normalize(version)) is not None


def sections(changelog: str) -> dict[str, str]:
    """Map every `## [label]` heading of a Keep-a-Changelog file to its body (link reference lines dropped)."""
    out: dict[str, str] = {}
    label: str | None = None
    buf: list[str] = []
    for line in changelog.splitlines():
        m = re.match(r"^## \[([^\]]+)\]", line)
        if m:
            if label is not None:
                out[label] = "\n".join(buf).strip()
            label, buf = m.group(1), []
        elif label is not None and not _LINK_REF_RE.match(line):
            buf.append(line)
    if label is not None:
        out[label] = "\n".join(buf).strip()
    return out


def find_section(changelog: str, version: str) -> tuple[str, str]:
    """(label, body) of the CHANGELOG section for `version`.

    The label is matched after PEP 440 normalisation, so `## [0.2.0-rc1]` serves version `0.2.0rc1`.
    A pre-release without a section of its own falls back to `[Unreleased]`. Raises LookupError.
    """
    secs = sections(changelog)
    wanted = normalize(version)
    for label, body in secs.items():
        try:
            if normalize(label) == wanted:
                return label, body
        except ValueError:
            continue
    if is_prerelease(version) and "Unreleased" in secs:
        return "Unreleased", secs["Unreleased"]
    hint = " (nor an [Unreleased] section to fall back to)" if is_prerelease(version) else ""
    raise LookupError(f"CHANGELOG.md has no '## [{version}]' section{hint}; write the notes before tagging")


def check(tag: str | None, root: Path = ROOT) -> dict[str, str]:
    """Tag, __version__ and CHANGELOG agree. Returns the facts the workflow needs; raises SystemExit otherwise."""
    version = read_version(root)
    try:
        normalize(version)
    except ValueError as e:
        raise SystemExit(f"__version__ = {version!r} is not a PEP 440 release version: {e}")
    if tag is not None:
        if not tag.startswith("v"):
            raise SystemExit(f"tag {tag!r} must look like vX.Y.Z or vX.Y.Z-rcN")
        try:
            tag_version = normalize(tag)
        except ValueError as e:
            raise SystemExit(f"tag {tag!r} is not a version tag: {e}")
        if tag_version != normalize(version):
            raise SystemExit(
                f"tag {tag} names version {tag_version} but src/aiit/__init__.py says {version!r}; "
                "bump __version__ (and CHANGELOG.md) on Main, then tag that commit"
            )
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    try:
        label, body = find_section(changelog, version)
    except LookupError as e:
        raise SystemExit(str(e))
    if not body.strip():
        raise SystemExit(f"CHANGELOG.md section [{label}] is empty; write the release notes before tagging")
    return {"version": version, "prerelease": "true" if is_prerelease(version) else "false", "notes_section": label}


def _human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GiB"


def describe_asset(name: str, version: str) -> str:
    """One-line purpose of a release asset, from its file name."""
    if name == "SHA256SUMS":
        return "SHA-256 of every other file here"
    if name.endswith(".whl"):
        return "Python wheel (Python 3.10 to 3.14, any OS): `pip install aiit` fetches this same file"
    if name == f"aiit-{version}.tar.gz":
        return "Source distribution"
    m = re.match(rf"^aiit-{re.escape(version)}-wheelhouse-(?P<os>[a-z]+)-(?P<arch>[a-z0-9_]+)\.zip$", name)
    if m:
        return f"Offline wheelhouse for {m['os']} {m['arch']}: the wheel plus every dependency for CPython 3.10 to 3.14, for `pip install --no-index`"
    m = re.match(rf"^aiit-{re.escape(version)}-(?P<os>[a-z]+)-(?P<arch>[a-z0-9_]+)\.(?:zip|tar\.gz)$", name)
    if m:
        return f"Standalone `aiit-agent` and `aiit-console` for {m['os']} {m['arch']} (no Python needed; unsigned, see below)"
    return "Release file"


def release_body(tag: str, assets_dir: Path | None, root: Path = ROOT) -> str:
    """The Markdown body of the GitHub Release for `tag`."""
    version = read_version(root)
    label, notes = find_section((root / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    parts: list[str] = []
    if label == "Unreleased":
        parts.append(
            f"Pre-release {version}. These notes are the `[Unreleased]` section of `CHANGELOG.md` at tag `{tag}`; "
            "the section is renamed when the final version ships.\n"
        )
    parts.append(notes.strip() + "\n")
    if assets_dir is not None:
        files = sorted(p for p in Path(assets_dir).iterdir() if p.is_file())
        if files:
            parts.append("## Assets\n")
            parts.append("| File | What it is | Size |")
            parts.append("|---|---|---|")
            for p in files:
                parts.append(f"| `{p.name}` | {describe_asset(p.name, version)} | {_human_size(p.stat().st_size)} |")
            parts.append("")
    parts.append(
        f"""## Verify a download

Every asset is listed in `SHA256SUMS` and carries a build-provenance attestation signed by GitHub for the workflow run that produced it.

```
sha256sum -c SHA256SUMS --ignore-missing            # Linux (macOS: shasum -a 256 -c; Windows: certutil -hashfile FILE SHA256)
gh attestation verify FILE --repo {REPO}           # GitHub CLI 2.49 or newer
```

## Unsigned binaries

The standalone `aiit-agent` and `aiit-console` builds are **not code-signed or notarised**. Windows SmartScreen and macOS Gatekeeper warn before the first run (macOS: `xattr -d com.apple.quarantine FILE` after you have verified the checksum). Where Python 3.10 to 3.14 is available, prefer the wheel or the offline wheelhouse; the binaries are for machines without Python. Authenticode signing and Apple notarisation are planned; the path is in `docs/release-process.md`.

## Install

```
python -m pip install aiit=={version}                                   # online
python -m pip install --no-index --find-links <unzipped wheelhouse> aiit  # offline
```
"""
    )
    return "\n".join(parts).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version", help="print __version__")
    s = sub.add_parser("check", help="tag, __version__ and CHANGELOG agree; prints GITHUB_OUTPUT lines")
    s.add_argument("--tag", help="git tag being released (vX.Y.Z); omitted on a rehearsal run")
    s = sub.add_parser("section", help="print the CHANGELOG section for __version__")
    s.add_argument("--tag")
    s = sub.add_parser("body", help="print the GitHub Release body")
    s.add_argument("--tag", required=True)
    s.add_argument("--assets", help="directory whose files are listed in the body")
    args = p.parse_args(argv)
    if args.cmd == "version":
        print(read_version())
    elif args.cmd == "check":
        facts = check(args.tag)
        for k, v in facts.items():
            print(f"{k}={v}")
        print(f"ok: version {facts['version']} (pre-release: {facts['prerelease']}), notes from [{facts['notes_section']}]", file=sys.stderr)
    elif args.cmd == "section":
        label, body = find_section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), read_version())
        print(f"## [{label}]\n\n{body}")
    elif args.cmd == "body":
        sys.stdout.write(release_body(args.tag, Path(args.assets) if args.assets else None))
    return 0


if __name__ == "__main__":
    sys.exit(main())
