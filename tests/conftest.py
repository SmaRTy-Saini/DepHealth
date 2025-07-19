import pytest
import json
from unittest.mock import patch, MagicMock
from dep_health import _VERSION_CACHE # Import the cache for clearing
import requests # Need to import requests to mock its exceptions

@pytest.fixture(autouse=True) # Automatically clears cache before each test
def clear_cache():
    _VERSION_CACHE.clear()
    yield

@pytest.fixture
def mock_package_json_healthy(tmp_path):
    content = {
        "name": "healthy-nodejs-project", "version": "1.0.0",
        "dependencies": {"express": "4.17.1", "lodash": "4.17.21"},
        "devDependencies": {"jest": "27.0.0"}
    }
    file_path = tmp_path / "package.json"
    file_path.write_text(json.dumps(content))
    return file_path

@pytest.fixture
def mock_requirements_txt_vulnerable(tmp_path):
    content = "flask==2.0.0\nrequests==2.25.1\n" # requests has known CVEs for older versions
    file_path = tmp_path / "requirements.txt"
    file_path.write_text(content)
    return file_path

@pytest.fixture
def mock_composer_json_outdated(tmp_path):
    content = {
        "name": "outdated/php-project", "require": {"monolog/monolog": "2.0.0"},
        "require-dev": {"phpunit/phpunit": "9.0.0"}
    }
    file_path = tmp_path / "composer.json"
    file_path.write_text(json.dumps(content))
    return file_path

@pytest.fixture
def mock_dephealthignore(tmp_path):
    content = "# Ignore list\nexpress\nmonolog/monolog\n*-test\nnodejs:jest"
    file_path = tmp_path / ".dephealthignore"
    file_path.write_text(content)
    return file_path

@pytest.fixture
def mock_npm_audit_output_healthy():
    return json.dumps({"auditReportVersion": 2, "vulnerabilities": {}})

@pytest.fixture
def mock_npm_audit_output_vulnerable():
    return json.dumps({
        "auditReportVersion": 2, "vulnerabilities": {
            "react": {"name": "react", "severity": "high", "via": [{"cve": "CVE-2023-REACT", "severity": "high", "title": "React issue"}], "fixAvailable": True},
            "lodash": {"name": "lodash", "severity": "moderate", "via": [{"cve": "CVE-2023-LODASH", "severity": "moderate", "title": "Lodash issue"}], "fixAvailable": False}
        }
    })

@pytest.fixture
def mock_pip_audit_output_vulnerable():
    return json.dumps([ # pip-audit output format
        {"package": {"name": "requests", "version": "2.25.1"}, "advisory": {"id": "GHSA-XXXX-YYYY-ZZZZ", "cve_id": "CVE-2023-REQUESTS", "link": "link", "title": "Requests vuln", "severity": "HIGH"}}
    ])

@pytest.fixture
def mock_composer_audit_output_vulnerable():
    return json.dumps([ # composer audit output format
        {"package": "monolog/monolog", "advisory": {"severity": "high", "title": "Monolog vuln", "link": "link", "id": "CVE-2023-MONOLOG"}}
    ])

@pytest.fixture
def mock_registry_versions():
    """Mocks various registry responses for different ecosystems."""
    with patch('dep_health.requests.get') as mock_get:
        def side_effect(url, timeout):
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            if "registry.npmjs.org/express" in url:
                mock_resp.json.return_value = {"dist-tags": {"latest": "4.17.1"}}
            elif "registry.npmjs.org/lodash" in url:
                mock_resp.json.return_value = {"dist-tags": {"latest": "4.17.21"}}
            elif "registry.npmjs.org/jest" in url:
                mock_resp.json.return_value = {"dist-tags": {"latest": "28.0.0"}} # Outdated dev dep
            elif "registry.npmjs.org/moment" in url:
                mock_resp.json.return_value = {"dist-tags": {"latest": "2.30.0"}}
            elif "registry.npmjs.org/axios" in url:
                mock_resp.json.return_value = {"dist-tags": {"latest": "1.0.0"}}
            elif "registry.npmjs.org/react" in url:
                mock_resp.json.return_value = {"dist-tags": {"latest": "18.3.0"}}
            elif "pypi.org/pypi/flask" in url:
                mock_resp.json.return_value = {"info": {"version": "2.0.0"}}
            elif "pypi.org/pypi/requests" in url:
                mock_resp.json.return_value = {"info": {"version": "2.31.0"}} # Newer
            elif "repo.packagist.org/packages/monolog/monolog" in url:
                mock_resp.json.return_value = {"packages": {"monolog/monolog": {"2.0.0": {}, "2.0.1": {}, "3.0.0": {}}}} # Newer
            elif "repo.packagist.org/packages/phpunit/phpunit" in url:
                mock_resp.json.return_value = {"packages": {"phpunit/phpunit": {"9.0.0": {}, "10.0.0": {}}}} # Newer
            else:
                mock_resp.status_code = 404
                mock_resp.raise_for_status.side_effect = requests.exceptions.HTTPError(response=mock_resp)
            return mock_resp
        mock_get.side_effect = side_effect
        yield mock_get