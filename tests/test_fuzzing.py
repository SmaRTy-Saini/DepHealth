import pytest
import json
import subprocess
import os
from unittest.mock import patch, MagicMock

# Define the path to your main script relative to this test file
SCRIPT_PATH = os.path.join(os.path.dirname(__file__), '..', 'dep_health.py')

@pytest.fixture
def run_cli_fuzz(tmp_path):
    """Fixture to run the CLI script in a temporary directory for fuzzing."""
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    yield lambda args: subprocess.run(
        [sys.executable, SCRIPT_PATH] + args,
        capture_output=True,
        text=True,
        check=False
    )
    os.chdir(original_cwd)

@pytest.fixture(autouse=True)
def mock_external_calls_fuzz():
    """Mocks external calls to prevent actual network/subprocess actions during fuzzing."""
    with patch('dep_health.requests.get'), \
         patch('dep_health.requests.post'), \
         patch('dep_health.subprocess.run') as mock_subprocess_run:
        
        # Mock audit tools to return empty or error if that's what we're testing
        mock_subprocess_run.return_value = MagicMock(
            stdout=json.dumps({"auditReportVersion": 2, "vulnerabilities": {}}),
            stderr="",
            returncode=0
        )
        yield {
            "subprocess_run": mock_subprocess_run
        }


def test_scan_with_malformed_package_json(run_cli_fuzz, tmp_path, mock_external_calls_fuzz):
    # Test case 1: Invalid JSON structure
    (tmp_path / "package.json").write_text("this is not valid json {")
    result = run_cli_fuzz(['scan'])
    assert result.returncode == 1
    assert "Error: Could not decode JSON from 'package.json'" in result.stderr

    # Test case 2: Valid JSON but missing 'dependencies' key
    (tmp_path / "package.json").write_text(json.dumps({"name": "test-project", "version": "1.0.0"}))
    result = run_cli_fuzz(['scan'])
    assert result.returncode == 0 # Should gracefully handle no dependencies
    assert "No immediate actions recommended" in result.stdout

    # Test case 3: Dependencies with malformed version strings
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"malformed-pkg": "not-a-version"}}))
    result = run_cli_fuzz(['scan'])
    assert result.returncode == 0
    assert "Warning: Could not parse version for 'malformed-pkg'" in result.stderr # Check for graceful warning


def test_scan_with_malformed_requirements_txt(run_cli_fuzz, tmp_path, mock_external_calls_fuzz):
    # Test case 1: Empty line
    (tmp_path / "requirements.txt").write_text("package-a==1.0.0\n\npackage-b==2.0.0")
    result = run_cli_fuzz(['scan'])
    assert result.returncode == 0
    assert "package-a" in result.stdout
    assert "package-b" in result.stdout

    # Test case 2: Completely invalid format
    (tmp_path / "requirements.txt").write_text("this is not a package line")
    result = run_cli_fuzz(['scan'])
    assert result.returncode == 0 # Should skip and not crash
    assert "No immediate actions recommended" in result.stdout # No packages found


def test_scan_with_malformed_composer_json(run_cli_fuzz, tmp_path, mock_external_calls_fuzz):
    # Test case 1: Invalid JSON structure
    (tmp_path / "composer.json").write_text("{{{{ not json")
    result = run_cli_fuzz(['scan'])
    assert result.returncode == 1
    assert "Error: Could not decode JSON from 'composer.json'" in result.stderr

    # Test case 2: Valid JSON but missing 'require' key
    (tmp_path / "composer.json").write_text(json.dumps({"name": "vendor/project"}))
    result = run_cli_fuzz(['scan'])
    assert result.returncode == 0 # Should gracefully handle no dependencies
    assert "No immediate actions recommended" in result.stdout