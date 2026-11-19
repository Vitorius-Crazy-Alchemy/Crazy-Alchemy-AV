import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import sys
import os

from backend.elevation_win import (
    is_elevated,
    build_task_scheduler_xml,
    register_elevation_bypass_task,
    dispatch_elevated_bypass_task,
    clean_non_elevated_autostart_entries,
    remove_elevation_bypass_tasks,
    unblock_directory_files
)


class TestElevationSubsystem(unittest.TestCase):
    """Test suite for Windows Task Scheduler elevation bypass and UAC suppression."""

    def test_is_elevated_type(self):
        result = is_elevated()
        self.assertIsInstance(result, bool)

    def test_build_task_scheduler_xml_demand(self):
        xml = build_task_scheduler_xml(
            command="C:\\Windows\\notepad.exe",
            arguments="--flag",
            work_dir="C:\\App",
            description="Test Task",
            on_logon=False,
            highest_privileges=True
        )
        self.assertIn("<RunLevel>HighestAvailable</RunLevel>", xml)
        self.assertIn("<LogonType>InteractiveToken</LogonType>", xml)
        self.assertIn("<Command>C:\\Windows\\notepad.exe</Command>", xml)
        self.assertIn("<Arguments>--flag</Arguments>", xml)
        self.assertIn("<WorkingDirectory>C:\\App</WorkingDirectory>", xml)
        self.assertNotIn("<LogonTrigger>", xml)

    def test_build_task_scheduler_xml_on_logon(self):
        xml = build_task_scheduler_xml(
            command="C:\\App\\app.exe",
            arguments="--minimized",
            on_logon=True,
            highest_privileges=True
        )
        self.assertIn("<RunLevel>HighestAvailable</RunLevel>", xml)
        self.assertIn("<LogonTrigger>", xml)
        self.assertIn("<Delay>PT3S</Delay>", xml)

    @patch("backend.elevation_win.subprocess.run")
    def test_dispatch_elevated_bypass_task_success(self, mock_run):
        # Query succeeds (task exists), run succeeds
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="SUCCESS", stderr=""),
            MagicMock(returncode=0, stdout="SUCCESS", stderr="")
        ]
        with patch("sys.platform", "win32"):
            ok = dispatch_elevated_bypass_task("CrazyAlchemy")
            self.assertTrue(ok)
            self.assertEqual(mock_run.call_count, 2)
            self.assertIn("CrazyAlchemy", mock_run.call_args_list[0][0][0])
            self.assertIn("/run", mock_run.call_args_list[1][0][0])

    @patch("backend.elevation_win.subprocess.run")
    def test_dispatch_elevated_bypass_task_not_found(self, mock_run):
        # Query fails (task doesn't exist)
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="ERROR: The system cannot find the file specified.")
        with patch("sys.platform", "win32"):
            ok = dispatch_elevated_bypass_task("NonExistentTask")
            self.assertFalse(ok)
            self.assertEqual(mock_run.call_count, 1)

    @patch("backend.elevation_win.subprocess.run")
    def test_register_elevation_bypass_task(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="SUCCESS", stderr="")
        with tempfile.TemporaryDirectory() as td:
            dummy_target = Path(td) / "CrazyAlchemy.exe"
            dummy_target.touch()
            with patch("sys.platform", "win32"):
                ok = register_elevation_bypass_task(target_exe=str(dummy_target), install_dir=Path(td))
                self.assertTrue(ok)
                self.assertGreaterEqual(mock_run.call_count, 2)

    @patch("backend.elevation_win.subprocess.run")
    def test_remove_elevation_bypass_tasks(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with patch("sys.platform", "win32"):
            ok = remove_elevation_bypass_tasks("CrazyAlchemy")
            self.assertTrue(ok)
            self.assertGreaterEqual(mock_run.call_count, 1)

    @patch("backend.elevation_win.subprocess.run")
    def test_unblock_directory_files(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as td:
            with patch("sys.platform", "win32"):
                unblock_directory_files(Path(td))
                self.assertEqual(mock_run.call_count, 1)
                self.assertIn("Unblock-File", mock_run.call_args[0][0][4])


if __name__ == "__main__":
    unittest.main()
