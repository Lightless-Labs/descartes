#!/usr/bin/env python3
"""Fake-fixture tests for the sourceable baked-Node CI helper."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


SCRIPT = Path(__file__).resolve().with_name("use-ci-node.sh")
NODE_VERSION = "v22.21.1"
NODE_CACHE_NAME = "node-v22.21.1-darwin-arm64"


class UseCINodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="descartes-ci-node-")
        self.root = Path(self.tempdir.name)
        self.fake_bin = self.root / "fake-bin"
        self.home = self.root / "home"
        self.log = self.root / "network.log"
        self.fake_bin.mkdir()
        self.home.mkdir()
        self._write_executable(
            self.fake_bin / "uname",
            """
            #!/bin/sh
            case "$1" in
              -s) printf '%s\\n' "$FAKE_UNAME_S" ;;
              -m) printf '%s\\n' "$FAKE_UNAME_M" ;;
              *) exit 2 ;;
            esac
            """,
        )
        self._write_executable(
            self.fake_bin / "curl",
            """
            #!/bin/sh
            printf 'curl was called\\n' >> "$FAKE_NETWORK_LOG"
            exit 99
            """,
        )
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(self.home),
                "PATH": os.pathsep.join((str(self.fake_bin), "/usr/bin", "/bin")),
                "FAKE_UNAME_S": "Darwin",
                "FAKE_UNAME_M": "arm64",
                "FAKE_NETWORK_LOG": str(self.log),
            }
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _write_executable(self, path: Path, body: str, mode: int = 0o755) -> None:
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
        path.chmod(mode)

    @property
    def cache(self) -> Path:
        return self.home / ".local" / NODE_CACHE_NAME

    def _write_node(self, version: str = NODE_VERSION) -> None:
        node = self.cache / "bin" / "node"
        node.parent.mkdir(parents=True)
        self._write_executable(
            node,
            f"""
            #!/bin/sh
            printf '%s\\n' {version}
            """,
        )

    def run_helper(self, shell: str = "bash", **overrides: str) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        env.update(overrides)
        fixture_path = env["PATH"]
        return subprocess.run(
            [
                shell,
                "-f",
                "-c",
                'set -euo pipefail; PATH="$2"; export PATH; source "$1"; printf "resolved=%s\\n" "$(command -v node)"; printf "version=%s\\n" "$(node --version)"',
                "use-ci-node-test",
                str(SCRIPT),
                fixture_path,
            ],
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )

    def assert_failure(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("resolved=", result.stdout)

    def test_valid_cache_is_used_and_prepended_without_download(self) -> None:
        self._write_node()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"resolved={self.cache / 'bin'}", result.stdout)
        self.assertIn(f"version={NODE_VERSION}", result.stdout)
        self.assertTrue(result.stdout.splitlines()[0].startswith("resolved="))
        self.assertFalse(self.log.exists())

    def test_valid_cache_is_usable_when_sourced_by_zsh(self) -> None:
        self._write_node()
        result = self.run_helper(shell="/bin/zsh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "", result.stderr)
        self.assertIn(f"resolved={self.cache / 'bin'}", result.stdout)
        self.assertIn(f"version={NODE_VERSION}", result.stdout)
        self.assertFalse(self.log.exists())

    def test_missing_cache_fails_without_creating_it(self) -> None:
        result = self.run_helper()
        self.assert_failure(result)
        self.assertFalse((self.home / ".local").exists())
        self.assertFalse(self.log.exists())

    def test_wrong_node_version_fails_without_path_change(self) -> None:
        self._write_node("v22.21.20")
        result = self.run_helper()
        self.assert_failure(result)
        self.assertFalse(self.log.exists())

    def test_non_executable_node_fails(self) -> None:
        self._write_node()
        node = self.cache / "bin" / "node"
        node.chmod(0o644)
        result = self.run_helper()
        self.assert_failure(result)

    def test_wrong_platform_fails_before_cache_access(self) -> None:
        self._write_node()
        result = self.run_helper(FAKE_UNAME_S="Linux")
        self.assert_failure(result)
        self.assertNotIn("resolved=", result.stdout)

    def test_invalid_home_fails_before_cache_access(self) -> None:
        self._write_node()
        result = self.run_helper(HOME="/")
        self.assert_failure(result)
        self.assertNotIn("resolved=", result.stdout)

    def test_symlink_cache_is_rejected(self) -> None:
        target = self.root / "node-target"
        target.mkdir()
        (target / "bin").mkdir()
        node = target / "bin" / "node"
        self._write_executable(
            node,
            f"""
            #!/bin/sh
            printf '%s\\n' {NODE_VERSION}
            """,
        )
        self.cache.parent.mkdir(parents=True)
        self.cache.symlink_to(target, target_is_directory=True)
        result = self.run_helper()
        self.assert_failure(result)
        self.assertTrue(self.cache.is_symlink())


if __name__ == "__main__":
    unittest.main()
