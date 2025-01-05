import unittest
from unittest.mock import patch, MagicMock
import io
import contextlib

from vulnerable_files.python.vulnerable_2 import execute_user_command as vulnerable_execute_user_command
from mitigated_files.vulnerable_2_mitigated import execute_user_command as mitigated_execute_user_command


class TestCommandExecution(unittest.TestCase):

    @patch("os.system")
    @patch("subprocess.run")
    def test_command_execution(self, mock_subprocess_run, mock_os_system):
        # Define the test command
        test_command = "echo Test"

        # Mock the return value of os.system
        mock_os_system.return_value = 0

        # Mock the return value of subprocess.run
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess_run.return_value = mock_result

        # Capture stdout for the vulnerable implementation
        with io.StringIO() as buf, contextlib.redirect_stdout(buf):
            vulnerable_execute_user_command(test_command)
            vulnerable_stdout = buf.getvalue().strip()

        # Ensure os.system was called with the correct command
        mock_os_system.assert_called_once_with(test_command)
        self.assertEqual(mock_os_system.call_count, 1, "os.system should be called once")

        # Capture stdout for the mitigated implementation
        with io.StringIO() as buf, contextlib.redirect_stdout(buf):
            mitigated_result = mitigated_execute_user_command(test_command)
            mitigated_stdout = buf.getvalue().strip()

        # Ensure subprocess.run was called with the correct command
        mock_subprocess_run.assert_called_once_with(test_command, shell=True, check=True)
        self.assertEqual(mock_subprocess_run.call_count, 1, "subprocess.run should be called once")

        # Verify stdout outputs are identical
        self.assertEqual(vulnerable_stdout, mitigated_stdout, "Captured stdout should be the same for both implementations")

        # Verify return codes match
        self.assertEqual(mock_os_system.return_value, mock_result.returncode, "Return codes should match for the same input")

    @patch("subprocess.run")
    def test_invalid_command_in_mitigated(self, mock_subprocess_run):
        # Test invalid input handling in the mitigated implementation
        with self.assertRaises(ValueError):
            mitigated_execute_user_command("")


if __name__ == "__main__":
    unittest.main()
