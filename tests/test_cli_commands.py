import pytest
import subprocess
import json
import os
from unittest.mock import patch, MagicMock

# Define the path to your main script relative to this test file
SCRIPT_PATH = os.path.join(os.path.dirname(__file__), '..', 'dep_health.py')

@pytest.fixture
def run_cli(tmp_path):
    """Fixture to run the CLI script in a temporary directory."""
    original_cwd = os.getcwd()
    os.chdir(tmp_path) # Change to temp dir for running CLI
    yield lambda args: subprocess.run(
        [sys.executable, SCRIPT_PATH] + args,
        capture_output=True,
        text=True,
        check=False # Do not raise exception for non-zero exit codes
    )
    os.chdir(original_cwd) # Change back

@pytest.fixture(autouse=True)
def mock_external_calls():
    """Mocks all external calls (requests, subprocess.run) for CLI tests."""
    with patch('dep_health.requests.get') as mock_requests_get, \
         patch('dep_health.requests.post') as mock_requests_post, \
         patch('dep_health.subprocess.run') as mock_subprocess_run:
        
        # Default mock for npm/pip/composer audit (healthy)
        mock_subprocess_run.return_value = MagicMock(
            stdout=json.dumps({"auditReportVersion": 2, "vulnerabilities": {}}),
            stderr="",
            returncode=0
        )
        # Default mock for registry versions (up-to-date)
        def mock_registry_side_effect(url, timeout):
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            if "registry.npmjs.org/" in url:
                pkg_name = url.split('/')[-1]
                mock_resp.json.return_value = {"dist-tags": {"latest": "1.0.0"}}
            elif "pypi.org/pypi/" in url:
                pkg_name = url.split('/')[-2]
                mock_resp.json.return_value = {"info": {"version": "2.0.0"}}
            elif "repo.packagist.org/packages/" in url:
                pkg_name = url.split('/')[-1].replace('.json', '')
                mock_resp.json.return_value = {"packages": {pkg_name: {"1.0.0": {}}}}
            else:
                mock_resp.status_code = 404
                mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)
            return mock_resp
        mock_requests_get.side_effect = mock_registry_side_effect

        # Default mock for GitHub API (success)
        mock_requests_post.return_value = MagicMock(
            status_code=201, json=lambda: {"html_url": "[http://mock-github-issue.com](http://mock-github-issue.com)"},
            raise_for_status=MagicMock(return_value=None)
        )
        yield {
            "requests_get": mock_requests_get,
            "requests_post": mock_requests_post,
            "subprocess_run": mock_subprocess_run
        }


def test_scan_basic_nodejs(run_cli, tmp_path, mock_external_calls):
    # Create a dummy package.json
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "1.0.0"}}))
    
    result = run_cli(['scan'])
    
    assert result.returncode == 0
    assert "Dependency Health Report" in result.stdout
    assert "Project Type: Nodejs" in result.stdout
    assert "Health Score: 100/100" in result.stdout
    assert "express: v1.0.0 (Latest: v1.0.0 | No known issues)" in result.stdout
    assert "No immediate actions recommended" in result.stdout
    assert mock_external_calls["requests_get"].called # Verify version fetch was attempted
    assert mock_external_calls["subprocess_run"].called # Verify audit was attempted


def test_scan_output_json(run_cli, tmp_path, mock_external_calls):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "1.0.0"}}))
    
    result = run_cli(['scan', '--output', 'report.json'])
    
    assert result.returncode == 0
    assert "Report successfully saved to 'report.json'" in result.stdout
    assert (tmp_path / "report.json").exists()
    
    with open(tmp_path / "report.json", 'r') as f:
        report_data = json.load(f)
        assert report_data['health_score'] == 100
        assert report_data['dependencies'][0]['name'] == 'express'


def test_scan_json_only_mode(run_cli, tmp_path, mock_external_calls):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "1.0.0"}}))
    
    result = run_cli(['scan', '--json-only'])
    
    assert result.returncode == 0
    # stdout should contain *only* the JSON
    try:
        json_output = json.loads(result.stdout)
        assert json_output['health_score'] == 100
        assert json_output['dependencies'][0]['name'] == 'express'
    except json.JSONDecodeError:
        pytest.fail("Output is not valid JSON in --json-only mode")
    
    assert "Starting Dependency Health Scan" not in result.stderr # No general output to stderr
    assert "Warning" not in result.stderr # Warnings should be suppressed


def test_scan_prod_only(run_cli, tmp_path, mock_external_calls):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"prod-pkg": "1.0.0"},
        "devDependencies": {"dev-pkg": "1.0.0"}
    }))

    result = run_cli(['scan', '--prod-only'])
    
    assert result.returncode == 0
    assert "prod-pkg" in result.stdout
    assert "dev-pkg" not in result.stdout # dev-pkg should be ignored


def test_scan_ignore_flag(run_cli, tmp_path, mock_external_calls):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"important-pkg": "1.0.0", "ignore-me-pkg": "1.0.0"}
    }))

    result = run_cli(['scan', '--ignore', 'ignore-me-pkg'])

    assert result.returncode == 0
    assert "important-pkg" in result.stdout
    assert "ignore-me-pkg" not in result.stdout


def test_scan_dephealthignore_file(run_cli, tmp_path, mock_external_calls):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"pkg-a": "1.0.0", "pkg-b": "1.0.0", "pkg-c": "1.0.0"}
    }))
    (tmp_path / ".dephealthignore").write_text("pkg-b\nnodejs:pkg-c")

    result = run_cli(['scan'])
    
    assert result.returncode == 0
    assert "pkg-a" in result.stdout
    assert "pkg-b" not in result.stdout # Ignored by general rule
    assert "pkg-c" not in result.stdout # Ignored by nodejs-specific rule


def test_scan_github_issue_creation(run_cli, tmp_path, mock_external_calls):
    # Mock a vulnerable scenario to trigger issue creation
    mock_external_calls["subprocess_run"].return_value = MagicMock(
        stdout=json.dumps({"auditReportVersion": 2, "vulnerabilities": {"react": {"severity": "high", "title": "React vuln"}}}),
        stderr="",
        returncode=1
    )
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"react": "17.0.0"}}))
    
    # Mock GITHUB_TOKEN environment variable
    with patch.dict(os.environ, {"GITHUB_TOKEN": "mock_token"}):
        result = run_cli(['scan', '--github', '--repo-owner', 'test-org', '--repo-name', 'test-repo', '--quiet'])
        
        assert result.returncode == 0
        assert "Successfully created GitHub issue" in result.stdout
        mock_external_calls["requests_post"].assert_called_once()
        
        # Verify the body of the GitHub issue
        call_args, call_kwargs = mock_external_calls["requests_post"].call_args
        issue_body = call_kwargs['json']['body']
        assert "## Dependency Health Dashboard Report" in issue_body
        assert "### Summary of Dependencies:" in issue_body
        assert "| Dependency | Current | Latest | Status | Vulnerability Info |" in issue_body
        assert "| `react` | `v17.0.0` | `v18.3.0` | 🚨 Vulnerable | High: React vuln (CVE: N/A)  |" in issue_body
        assert "### Recommendations:" in issue_body
        assert "Fix react: React vuln" in issue_body


def test_update_check_command_new_version(run_cli, mock_external_calls):
    # Mock requests.get for update check to return a newer version
    mock_external_calls["requests_get"].side_effect = [
        MagicMock(status_code=200, json=lambda: {"tag_name": "v999.0.0"}, raise_for_status=MagicMock(return_value=None))
    ] + list(mock_external_calls["requests_get"].side_effect) # Keep other side effects for scan

    result = run_cli(['update-check'])
    assert result.returncode == 0
    assert "A new version is available: v999.0.0" in result.stdout
    assert "Please update your tool by running" in result.stdout


def test_update_check_command_latest_version(run_cli, mock_external_calls):
    # Mock requests.get for update check to return current version
    mock_external_calls["requests_get"].side_effect = [
        MagicMock(status_code=200, json=lambda: {"tag_name": f"v{dep_health.__version__}"}, raise_for_status=MagicMock(return_value=None))
    ] + list(mock_external_calls["requests_get"].side_effect)

    result = run_cli(['update-check'])
    assert result.returncode == 0
    assert f"You are running the latest version: v{dep_health.__version__}" in result.stdout

def test_scan_no_project_file(run_cli, tmp_path):
    # No package.json, requirements.txt, or composer.json
    result = run_cli(['scan'])
    assert result.returncode == 1
    assert "Error: No recognized project file found" in result.stderr