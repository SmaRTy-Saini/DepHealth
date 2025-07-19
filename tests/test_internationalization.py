import pytest
import subprocess
import os
import json
from unittest.mock import patch, MagicMock

# Define the path to your main script relative to this test file
SCRIPT_PATH = os.path.join(os.path.dirname(__file__), '..', 'dep_health.py')

@pytest.fixture
def run_cli_with_locale(tmp_path):
    """Fixture to run the CLI script with a specific locale environment."""
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    yield lambda args, lang_code: subprocess.run(
        [sys.executable, SCRIPT_PATH] + args,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, 'LANG': f'{lang_code}_{lang_code.upper()}.UTF-8', 'LC_ALL': f'{lang_code}_{lang_code.upper()}.UTF-8'}
    )
    os.chdir(original_cwd)

@pytest.fixture(autouse=True)
def mock_external_calls_i18n():
    """Mocks all external calls (requests, subprocess.run) for I18n tests."""
    with patch('dep_health.requests.get') as mock_requests_get, \
         patch('dep_health.subprocess.run') as mock_subprocess_run:
        
        mock_subprocess_run.return_value = MagicMock(
            stdout=json.dumps({"auditReportVersion": 2, "vulnerabilities": {}}),
            stderr="",
            returncode=0
        )
        def mock_registry_side_effect(url, timeout):
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            if "registry.npmjs.org/" in url:
                mock_resp.json.return_value = {"dist-tags": {"latest": "1.0.0"}}
            return mock_resp
        mock_requests_get.side_effect = mock_registry_side_effect
        yield


def test_scan_output_in_french(run_cli_with_locale, tmp_path):
    # Create a dummy package.json
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "1.0.0"}}))

    # Create the locale directory and a dummy .mo file for French
    # This simulates the translation being available
    locale_dir = tmp_path / "locale" / "fr" / "LC_MESSAGES"
    locale_dir.mkdir(parents=True, exist_ok=True)
    (locale_dir / "dep_health.mo").touch() # Just needs to exist for gettext to try loading it

    # Call the CLI with French locale
    result = run_cli_with_locale(['scan'], 'fr')

    assert result.returncode == 0
    # Check for a specific translated string from dep_health.po
    assert "Rapport de santé des dépendances" in result.stdout
    assert "Type de projet : Nodejs" in result.stdout
    assert "Score de santé : 100/100" in result.stdout
    assert "Aucune action immédiate recommandée." in result.stdout
    # Ensure warnings about missing libraries are also translated if they appear
    assert "Avertissement : Colorama introuvable" not in result.stderr
    assert "Avertissement : Bibliothèque de 'packaging' introuvable" not in result.stderr

def test_scan_output_default_english_if_no_locale_found(run_cli_with_locale, tmp_path):
    # Create a dummy package.json
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "1.0.0"}}))

    # Do NOT create locale/es/LC_MESSAGES/dep_health.mo
    # This simulates a user setting LANG but translation files are missing

    result = run_cli_with_locale(['scan'], 'es')

    assert result.returncode == 0
    # Check for English string even if locale was set to 'es'
    assert "Dependency Health Report" in result.stdout
    assert "Health Score: 100/100" in result.stdout
    assert "No immediate actions recommended" in result.stdout
    # Check for the warning about missing translation
    assert "Warning: Could not load translations for 'es'. Defaulting to English." in result.stderr

def test_scan_output_default_english_if_no_lang_set(run_cli_with_locale, tmp_path):
    # Create a dummy package.json
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "1.0.0"}}))

    # Do NOT set LANG environment variable (default behavior)
    result = subprocess.run(
        [sys.executable, SCRIPT_PATH, 'scan'],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path # Run in temp dir
    )

    assert result.returncode == 0
    # Should be English (default)
    assert "Dependency Health Report" in result.stdout
    assert "Health Score: 100/100" in result.stdout
    assert "No immediate actions recommended" in result.stdout
    # No translation warning
    assert "Warning: Could not load translations" not in result.stderr