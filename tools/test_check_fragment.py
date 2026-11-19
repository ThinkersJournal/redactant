#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Tests for tools/check-fragment.py, run against real throwaway git repositories: python tools/test_check_fragment.py"""
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "check-fragment.py")
ROOT = '[package]\nname = "r"\nversion = "0.1.13"\n'
CRATE = '[package]\nname = "{n}"\nversion = "{v}"\n'
FRAG = "kind: x\n---\nbody\n"


def run(cwd, *args):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True).stdout


def write(repo, rel, text):
    path = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as f:
        f.write(text)


class Case(unittest.TestCase):
    def repo(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        r = d.name
        run(r, "git", "init", "-q", "-b", "main")
        run(r, "git", "config", "user.email", "t@example.invalid")
        run(r, "git", "config", "user.name", "t")
        write(r, "Cargo.toml", ROOT)
        write(r, "old/Cargo.toml", CRATE.format(n="old", v="0.1.13"))
        run(r, "git", "add", "-A")
        run(r, "git", "commit", "-q", "-m", "base")
        run(r, "git", "checkout", "-q", "-b", "pr")
        return r

    def check(self, r):
        run(r, "git", "add", "-A")
        run(r, "git", "commit", "-q", "-m", "pr")
        p = subprocess.run([sys.executable, SCRIPT, "main"], cwd=r, capture_output=True, text=True)
        return p.returncode, p.stdout

    def test_new_crate_at_base_version_with_one_fragment_passes(self):
        r = self.repo()
        write(r, "new/Cargo.toml", CRATE.format(n="new", v="0.1.13"))
        write(r, "changelog.d/a.md", FRAG)
        self.assertEqual(self.check(r), (0, "check-fragment: ok\n"))

    def test_positive_control_bump_of_an_existing_crate_still_fails(self):
        r = self.repo()
        write(r, "old/Cargo.toml", CRATE.format(n="old", v="0.1.14"))
        write(r, "changelog.d/a.md", FRAG)
        code, out = self.check(r)
        self.assertEqual(code, 1)
        self.assertIn("both bumps a version and adds a fragment", out)

    def test_new_crate_at_a_different_version_is_a_bump(self):
        r = self.repo()
        write(r, "new/Cargo.toml", CRATE.format(n="new", v="0.2.0"))
        write(r, "changelog.d/a.md", FRAG)
        code, out = self.check(r)
        self.assertEqual(code, 1)
        self.assertIn("both bumps a version and adds a fragment", out)

    def test_new_crate_without_a_fragment_fails(self):
        r = self.repo()
        write(r, "new/Cargo.toml", CRATE.format(n="new", v="0.1.13"))
        code, out = self.check(r)
        self.assertEqual(code, 1)
        self.assertIn("no CHANGELOG fragment", out)

    def test_new_crate_with_two_fragments_fails(self):
        r = self.repo()
        write(r, "new/Cargo.toml", CRATE.format(n="new", v="0.1.13"))
        write(r, "changelog.d/a.md", FRAG)
        write(r, "changelog.d/b.md", FRAG)
        code, out = self.check(r)
        self.assertEqual(code, 1)
        self.assertIn("2 fragments", out)

    def test_plain_fragment_only_passes(self):
        r = self.repo()
        write(r, "changelog.d/a.md", FRAG)
        self.assertEqual(self.check(r)[0], 0)


if __name__ == "__main__":
    unittest.main()
