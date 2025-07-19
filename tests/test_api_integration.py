import pytest
from unittest.mock import patch, MagicMock
from dep_health import (
    _fetch_latest_version_npm, _fetch_latest_version_pypi, _fetch_latest_version_composer,
    fetch_latest_versions_parallel, _VERSION_CACHE
)
import requests # Need to import requests to mock its exceptions

@pytest.fixture(autouse=True) # Ensures cache is clear before each test
def clear_cache():
    _VERSION_CACHE.clear()
    yield

@patch('dep_health.requests.get')
def test_fetch_latest_version_npm_success(mock_get):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"dist-tags": {"latest": "4.1.0"}}
    mock_get.return_value = mock_response

    version = _fetch_latest_version_npm("my-npm-package", quiet_mode=True)
    assert version == "4.1.0"
    mock_get.assert_called_once_with("[https://registry.npmjs.org/my-npm-package](https://registry.npmjs.org/my-npm-package)", timeout=10)
    assert _VERSION_CACHE["my-npm-package"] == "4.1.0"

@patch('dep_health.requests.get')
def test_fetch_latest_version_pypi_success(mock_get):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"info": {"version": "2.5.0"}}
    mock_get.return_value = mock_response

    version = _fetch_latest_version_pypi("my-python-package", quiet_mode=True)
    assert version == "2.5.0"
    mock_get.assert_called_once_with("[https://pypi.org/pypi/my-python-package/json](https://pypi.org/pypi/my-python-package/json)", timeout=10)
    assert _VERSION_CACHE["my-python-package"] == "2.5.0"

@patch('dep_health.requests.get')
def test_fetch_latest_version_composer_success(mock_get):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "packages": {
            "vendor/pkg": {
                "1.0.0": {}, "1.0.1": {}, "2.0.0": {}, "2.0.0-beta": {} # Ensure latest stable is picked
            }
        }
    }
    mock_get.return_value = mock_response

    version = _fetch_latest_version_composer("vendor/pkg", quiet_mode=True)
    assert version == "2.0.0" # Should pick latest stable
    mock_get.assert_called_once_with("[https://repo.packagist.org/packages/vendor/pkg.json](https://repo.packagist.org/packages/vendor/pkg.json)", timeout=10)
    assert _VERSION_CACHE["vendor/pkg"] == "2.0.0"

@patch('dep_health.requests.get')
def test_fetch_latest_versions_parallel_caching(mock_get):
    # Setup mock to only respond to first call, subsequent calls should be cached
    mock_response_1 = MagicMock()
    mock_response_1.raise_for_status.return_value = None
    mock_response_1.json.return_value = {"dist-tags": {"latest": "1.0.0"}}

    mock_response_2 = MagicMock()
    mock_response_2.raise_for_status.return_value = None
    mock_response_2.json.return_value = {"dist-tags": {"latest": "2.0.0"}}

    mock_get.side_effect = [mock_response_1, mock_response_2] # Only two distinct calls will be made

    packages = {"pkg-a": "0.9.0", "pkg-b": "1.9.0"}
    
    # First call, should hit network for both, and populate cache
    results1 = fetch_latest_versions_parallel(packages, "nodejs", quiet_mode=True)
    assert results1["pkg-a"] == "1.0.0"
    assert results1["pkg-b"] == "2.0.0"
    assert mock_get.call_count == 2
    assert _VERSION_CACHE["pkg-a"] == "1.0.0"
    assert _VERSION_CACHE["pkg-b"] == "2.0.0"
    
    # Second call for the same packages, should use cache for both, no new network calls
    mock_get.reset_mock() # Clear call count for the next assertion
    results2 = fetch_latest_versions_parallel(packages, "nodejs", quiet_mode=True)
    assert results2["pkg-a"] == "1.0.0"
    assert results2["pkg-b"] == "2.0.0"
    assert mock_get.call_count == 0 # No new network calls

@patch('dep_health.requests.get')
def test_fetch_latest_versions_parallel_mixed_ecosystems(mock_get):
    mock_response_npm = MagicMock()
    mock_response_npm.json.return_value = {"dist-tags": {"latest": "1.0.0"}}
    mock_response_pypi = MagicMock()
    mock_response_pypi.json.return_value = {"info": {"version": "2.0.0"}}
    
    def side_effect(url, timeout):
        if "registry.npmjs.org" in url:
            return mock_response_npm
        elif "pypi.org" in url:
            return mock_response_pypi
        return MagicMock(status_code=404, raise_for_status=MagicMock(side_effect=requests.exceptions.HTTPError()))

    mock_get.side_effect = side_effect

    npm_deps = {"express": "0.9.0"}
    python_deps = {"flask": "1.9.0"}

    npm_results = fetch_latest_versions_parallel(npm_deps, "nodejs", quiet_mode=True)
    assert npm_results["express"] == "1.0.0"

    pypi_results = fetch_latest_versions_parallel(python_deps, "python", quiet_mode=True)
    assert pypi_results["flask"] == "2.0.0"

    assert mock_get.call_count == 2 # One for npm, one for pypi