#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that a pull request carries exactly one CHANGELOG fragment, or bumps the version itself.

    python tools/check-fragment.py <base-ref>        e.g. origin/main

Compares HEAD with the merge base of <base-ref>. A PR must do exactly one of:

  * add one `changelog.d/<topic>.md` (not README.md) and leave every version alone; or
  * change a crate version itself (a release-line backport, or a PR opened before the repo moved to fragments) and add
    no fragment.

Doing both, adding two fragments, or doing neither fails, with the reason. Standard library only.

One exception to "leave every version alone": a manifest the PR ADDS (a new crate in the workspace) must carry a version
line, and it is not a bump when that version equals the project's current version at the merge base (the stamp then moves
every crate together). A real bump of an existing crate, or a new manifest whose version differs from the base version,
still counts as a bump. Tests: tools/test_check_fragment.py.
"""
import re
import subprocess
import sys


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def version_lines(diff):
    return [
        l for l in diff.splitlines()
        if re.match(r'^[+-]\s*version\s*=\s*"\d+\.\d+\.\d+[^"]*"', l)
        and not re.search(r"path\s*=|git\s*=|registry\s*=", l)
    ]


def base_version(base):
    """The project's current version at `base`: root [package] or [workspace.package] version, else None."""
    try:
        text = git("show", f"{base}:Cargo.toml")
    except subprocess.CalledProcessError:
        return None
    for table in ("workspace.package", "package"):
        m = re.search(r"(?ms)^\[" + re.escape(table) + r"\]\s*$(.*?)(?=^\[|\Z)", text)
        if m:
            v = re.search(r'(?m)^\s*version\s*=\s*"(\d+\.\d+\.\d+[^"]*)"', m.group(1))
            if v:
                return v.group(1)
    return None


def is_bump(diff, added_manifest, current):
    """Does this manifest's diff change a crate version? A manifest added at the current version does not."""
    lines = version_lines(diff)
    if added_manifest and current:
        lines = [l for l in lines if not re.match(r'^\+\s*version\s*=\s*"' + re.escape(current) + '"', l)]
    return bool(lines)


def judge(added_fragments, version_changed):
    if added_fragments and version_changed:
        return "this PR both bumps a version and adds a fragment: do one (fragments, once the PM stamps the version)"
    if version_changed or len(added_fragments) == 1:
        return None
    if not added_fragments:
        return "this PR has no CHANGELOG fragment: add changelog.d/<topic>.md (see changelog.d/README.md)"
    return f"this PR adds {len(added_fragments)} fragments ({', '.join(added_fragments)}): exactly one"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    base = git("merge-base", sys.argv[1], "HEAD").strip()
    names = git("diff", "--name-status", "--diff-filter=A", base, "HEAD").splitlines()
    added = [n.split("\t", 1)[1] for n in names if re.match(r"^A\tchangelog\.d/(?!README\.md$)[^/]+\.md$", n)]
    status = [n.split("	", 1) for n in git("diff", "--name-status", base, "HEAD").splitlines()]
    manifests = [(st[0], path) for st, path in status if path.endswith("Cargo.toml")]
    current = base_version(base)
    changed = any(is_bump(git("diff", "-U0", base, "HEAD", "--", p), st == "A", current) for st, p in manifests)
    why = judge(added, changed)
    if why:
        print("check-fragment: " + why)
        return 1
    print("check-fragment: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
