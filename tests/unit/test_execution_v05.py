from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.execution import (
    BubblewrapExecutor,
    DenyExecutor,
    DockerExecutor,
    ExecutionError,
    ExecutionLimits,
    ManagedProcess,
    WindowsJobExecutor,
    executor_from_options,
)


class ExecutionV05Tests(unittest.TestCase):
    def test_limits_and_backend_inputs_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            ExecutionLimits(memory_mb=15)
        with self.assertRaises(ValueError):
            ExecutionLimits(cpu_count=float("nan"))
        with self.assertRaises(ValueError):
            DockerExecutor("bad image")
        with self.assertRaises(ExecutionError):
            executor_from_options("docker")
        with self.assertRaises(ExecutionError):
            DenyExecutor().spawn(["server"], cwd=None, env={})

    def test_docker_command_enforces_isolation_without_argv_secrets(self) -> None:
        fake_process = mock.Mock()
        with (
            mock.patch(
                "mcp_tool_card_linter.execution.shutil.which",
                return_value="/usr/bin/docker",
            ),
            mock.patch(
                "mcp_tool_card_linter.execution.subprocess.Popen",
                return_value=fake_process,
            ) as popen,
        ):
            managed = DockerExecutor(
                "registry.example/server@sha256:" + "a" * 64,
                limits=ExecutionLimits(
                    memory_mb=256,
                    cpu_count=0.5,
                    process_count=12,
                    temporary_mb=8,
                ),
            ).spawn(
                ["server", "--mode", "mcp"],
                cwd=None,
                env={"PATH": "/host/bin", "API_TOKEN": "super-secret", "LANG": "C"},
            )

        self.assertIs(managed.process, fake_process)
        command = popen.call_args.args[0]
        command_text = " ".join(command)
        for required in (
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "no-new-privileges=true",
            "--pids-limit 12",
            "--memory 256m",
            "--memory-swap 256m",
            "--cpus 0.5",
        ):
            self.assertIn(required, command_text)
        self.assertNotIn("super-secret", command_text)
        self.assertIn("API_TOKEN", command)
        self.assertNotIn("PATH", command)

    def test_docker_refuses_implicit_host_working_directory(self) -> None:
        with self.assertRaises(ExecutionError):
            DockerExecutor("example/server:1").spawn(
                ["server"], cwd=str(ROOT), env={}
            )

    def test_bubblewrap_builds_read_only_no_network_namespace(self) -> None:
        fake_process = mock.Mock()
        with (
            tempfile.TemporaryDirectory() as tmpdir,
            mock.patch(
                "mcp_tool_card_linter.execution._running_on_linux",
                return_value=True,
            ),
            mock.patch(
                "mcp_tool_card_linter.execution.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ),
            mock.patch(
                "mcp_tool_card_linter.execution.subprocess.Popen",
                return_value=fake_process,
            ) as popen,
        ):
            managed = BubblewrapExecutor().spawn(
                ["/usr/bin/server"], cwd=tmpdir, env={"LANG": "C"}
            )

        self.assertIs(managed.process, fake_process)
        command = popen.call_args.args[0]
        self.assertIn("--unshare-all", command)
        self.assertNotIn("--share-net", command)
        self.assertIn("--ro-bind", command)
        self.assertIn("--tmpfs", command)
        self.assertIn("--die-with-parent", command)

    def test_managed_release_is_idempotent(self) -> None:
        released: list[bool] = []
        managed = ManagedProcess(mock.Mock(), lambda: released.append(True))
        managed.release()
        managed.release()
        self.assertEqual(released, [True])

    @unittest.skipUnless(os.name == "nt", "Windows Job Object integration")
    def test_windows_job_runs_and_releases_a_real_process(self) -> None:
        managed = WindowsJobExecutor().spawn(
            [sys.executable, "-c", "pass"], cwd=None, env=os.environ.copy()
        )
        self.assertEqual(managed.process.wait(timeout=10), 0)
        managed.release()


if __name__ == "__main__":
    unittest.main()
