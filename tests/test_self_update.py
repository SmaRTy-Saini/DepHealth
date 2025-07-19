import pytest
from unittest.mock import patch, MagicMock
from dep_health import check_for_updates, __version__, TOOL_REPO_URL

@patch('dep_health.requests.get')
@patch('dep_health.print_colored') # Mock print_colored to capture output
class TestSelfUpdate:
    def test_new_version_available(self, mock_print_colored, mock_requests_get):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"tag_name": "v999.0.0"} # Mock a very new version
        mock_requests_get.return_value = mock_response

        with patch('dep_health.__version__', "0.1.0"): # Ensure current version is old
            result = check_for_updates()
            assert result is True
            mock_print_colored.assert_any_call(
                pytest.match(r"A new version is available:.*v999\.0\.0.*"),
                pytest.anything(), pytest.anything()
            )

    def test_already_latest_version(self, mock_print_colored, mock_requests_get):
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"tag_name": f"v{__version__}"} # Mock current version as latest
        mock_requests_get.return_value = mock_response

        result = check_for_updates()
        assert result is False
        mock_print_colored.assert_any_call(
            pytest.match(f"You are running the latest version: v{__version__}"),
            pytest.anything()
        )

    def test_github_api_error(self, mock_print_colored, mock_requests_get):
        mock_requests_get.side_effect = requests.exceptions.RequestException("Network error")

        result = check_for_updates()
        assert result is False
        mock_print_colored.assert_any_call(
            pytest.match(r"Error: Could not check for updates \(network or API error\).*"),
            pytest.anything(), file=sys.stderr # Errors go to stderr
        )