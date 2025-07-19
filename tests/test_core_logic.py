import pytest
import json
from unittest.mock import patch, MagicMock
from dep_health import analyze_dependencies, calculate_health_score, generate_report_json, generate_markdown_table_for_github, detect_project_type, read_ignore_file, load_package_json, load_requirements_txt, load_composer_json

# Mock subprocess.run for all audit calls
@patch('dep_health.subprocess.run')
# Mock requests.get for all registry API calls
@patch('dep_health.requests.get')
class TestAnalyzeDependencies:
    def test_nodejs_healthy_scan(self, mock_requests_get, mock_subprocess_run,
                                mock_npm_audit_output_healthy, mock_registry_versions,
                                mock_package_json_healthy, tmp_path):
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_npm_audit_output_healthy, stderr="", returncode=0
        )
        with patch('os.getcwd', return_value=str(tmp_path)):
            package_data = load_package_json(mock_package_json_healthy.name)
            dep_statuses, outdated_count, total_vuln_score, total_deps = analyze_dependencies(package_data, "nodejs")

        assert total_deps == 3 # express, lodash, jest (dev dep)
        assert outdated_count == 1 # jest is outdated in mock registry
        assert total_vuln_score == 0
        assert len(dep_statuses) == 3

        jest_status = next(d for d in dep_statuses if d['name'] == 'jest')
        assert jest_status['is_outdated'] is True
        assert jest_status['latest_version'] == '28.0.0'

    def test_nodejs_prod_only_scan(self, mock_requests_get, mock_subprocess_run,
                                   mock_npm_audit_output_healthy, mock_registry_versions,
                                   mock_package_json_healthy, tmp_path):
        mock_subprocess_run.return_value = MagicMock(stdout=mock_npm_audit_output_healthy, stderr="", returncode=0)
        with patch('os.getcwd', return_value=str(tmp_path)):
            package_data = load_package_json(mock_package_json_healthy.name)
            dep_statuses, outdated_count, total_vuln_score, total_deps = analyze_dependencies(package_data, "nodejs", prod_only=True)

        assert total_deps == 2 # express, lodash (jest is skipped)
        assert outdated_count == 0 # jest (outdated) was skipped
        assert total_vuln_score == 0
        assert len(dep_statuses) == 2
        assert 'jest' not in [d['name'] for d in dep_statuses]

    def test_nodejs_vulnerable_scan(self, mock_requests_get, mock_subprocess_run,
                                  mock_npm_audit_output_vulnerable, mock_registry_versions,
                                  mock_package_json_vulnerable, tmp_path):
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_npm_audit_output_vulnerable, stderr="", returncode=1
        )
        with patch('os.getcwd', return_value=str(tmp_path)):
            package_data = load_package_json(mock_package_json_vulnerable.name)
            dep_statuses, outdated_count, total_vuln_score, total_deps = analyze_dependencies(package_data, "nodejs")

        assert total_deps == 2
        assert outdated_count == 1 # React is outdated in mock
        assert total_vuln_score == 0.7 + 0.4 # High (React) + Moderate (Lodash)
        assert len(dep_statuses) == 2

        react_status = next(d for d in dep_statuses if d['name'] == 'react')
        assert react_status['is_outdated'] is True
        assert react_status['vulnerable'] is True
        assert react_status['vulnerability_severity'] == 'high'
        assert react_status['vulnerability_cve'] == 'CVE-2023-REACT'
        assert react_status['vulnerability_fix_available'] is True

        lodash_status = next(d for d in dep_statuses if d['name'] == 'lodash')
        assert lodash_status['vulnerable'] is True
        assert lodash_status['vulnerability_severity'] == 'moderate'
        assert lodash_status['vulnerability_cve'] == 'CVE-2023-LODASH'
        assert lodash_status['vulnerability_fix_available'] is False

    def test_python_vulnerable_scan(self, mock_requests_get, mock_subprocess_run,
                                    mock_pip_audit_output_vulnerable, mock_registry_versions,
                                    mock_requirements_txt_vulnerable, tmp_path):
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_pip_audit_output_vulnerable, stderr="", returncode=1
        )
        with patch('os.getcwd', return_value=str(tmp_path)):
            package_data = load_requirements_txt(mock_requirements_txt_vulnerable.name)
            dep_statuses, outdated_count, total_vuln_score, total_deps = analyze_dependencies(package_data, "python")

        assert total_deps == 2
        assert outdated_count == 1 # requests is outdated
        assert total_vuln_score == 0.7 # High severity from mock pip-audit
        assert len(dep_statuses) == 2

        requests_status = next(d for d in dep_statuses if d['name'] == 'requests')
        assert requests_status['is_outdated'] is True
        assert requests_status['vulnerable'] is True
        assert requests_status['vulnerability_severity'] == 'high'
        assert requests_status['vulnerability_cve'] == 'CVE-2023-REQUESTS'

    def test_php_outdated_scan(self, mock_requests_get, mock_subprocess_run,
                               mock_composer_audit_output_vulnerable, mock_registry_versions,
                               mock_composer_json_outdated, tmp_path):
        # Mock composer audit to return no vulnerabilities for this test
        mock_subprocess_run.return_value = MagicMock(stdout=json.dumps([]), stderr="", returncode=0)
        with patch('os.getcwd', return_value=str(tmp_path)):
            package_data = load_composer_json(mock_composer_json_outdated.name)
            dep_statuses, outdated_count, total_vuln_score, total_deps = analyze_dependencies(package_data, "php")
        
        assert total_deps == 2 # monolog, phpunit
        assert outdated_count == 2 # both are outdated in mock registry
        assert total_vuln_score == 0
        assert len(dep_statuses) == 2

        monolog_status = next(d for d in dep_statuses if d['name'] == 'monolog/monolog')
        assert monolog_status['is_outdated'] is True
        assert monolog_status['latest_version'] == '3.0.0' # Latest stable

    def test_ignore_flag_and_file(self, mock_requests_get, mock_subprocess_run,
                                 mock_npm_audit_output_vulnerable, mock_registry_versions,
                                 mock_package_json_vulnerable, mock_dephealthignore, tmp_path):
        mock_subprocess_run.return_value = MagicMock(
            stdout=mock_npm_audit_output_vulnerable, stderr="", returncode=1
        )
        with patch('os.getcwd', return_value=str(tmp_path)):
            package_data = load_package_json(mock_package_json_vulnerable.name)
            
            # Combine ignore from file and from command-line
            # This is how dep_health.py read_ignore_file will work with current_ecosystem
            # For this test, assume nodejs is the current ecosystem for file parsing.
            ignored_from_file = read_ignore_file(mock_dephealthignore.name, current_ecosystem="nodejs")
            
            # 'express' (generic), 'monolog/monolog' (generic), 'jest' (nodejs specific)
            # mock_dephealthignore contains: express, monolog/monolog, *-test, nodejs:jest
            
            # The mock_package_json_vulnerable has 'react' and 'lodash'
            # 'jest' is not in this package.json
            
            # Final ignored set from file (for nodejs): {'express', 'monolog/monolog', '*-test', 'jest'}
            
            # Simulate CLI ignore being added
            cli_ignored_packages = {'react'}
            combined_ignored = ignored_from_file.union(cli_ignored_packages)

            dep_statuses, outdated_count, total_vuln_score, total_deps = \
                analyze_dependencies(package_data, "nodejs", ignore_packages=combined_ignored)
        
        # Original dependencies: 'react', 'lodash'
        # Ignored: 'react' (from CLI or file if it matched), 'jest' (from file, but not in package_data), 'express' (from file, not in package_data)
        # Result: 'react' should be ignored. 'lodash' should be processed.
        
        assert total_deps == 1 # Only lodash remains after filtering
        assert outdated_count == 0 # React was outdated, but ignored
        assert total_vuln_score == 0.4 # Only lodash vulnerability counts
        assert len(dep_statuses) == 1
        assert dep_statuses[0]['name'] == 'lodash'
        assert 'react' not in [d['name'] for d in dep_statuses]


class TestHealthScoreCalculation:
    def test_health_score_perfect(self):
        assert calculate_health_score(0, 0, 10) == 100

    def test_health_score_all_outdated_no_vulns(self):
        assert calculate_health_score(10, 0, 10) == 50

    def test_health_score_no_outdated_critical_vuln(self):
        assert calculate_health_score(0, 1.0, 10) == 50

    def test_health_score_mixed_issues(self):
        assert calculate_health_score(5, 0.7, 10) == 72

    def test_health_score_zero_dependencies(self):
        assert calculate_health_score(0, 0, 0) == 100

class TestReportGeneration:
    def setup_method(self):
        self.sample_dep_statuses = [
            {"name": "express", "current_version": "4.17.1", "latest_version": "4.17.1", "is_outdated": False, "vulnerable": False, "vulnerability_severity": "N/A", "vulnerability_cve": "N/A", "vulnerability_fix_available": False, "vulnerability_overview": "No known vulnerabilities."},
            {"name": "react", "current_version": "17.0.0", "latest_version": "18.0.0", "is_outdated": True, "vulnerable": True, "vulnerability_severity": "high", "vulnerability_cve": "CVE-2023-REACT", "vulnerability_fix_available": True, "vulnerability_overview": "Critical issue in React."},
            {"name": "lodash", "current_version": "4.17.20", "latest_version": "4.17.21", "is_outdated": True, "vulnerable": False, "vulnerability_severity": "N/A", "vulnerability_cve": "N/A", "vulnerability_fix_available": False, "vulnerability_overview": "No known vulnerabilities."}
        ]
        self.health_score = 60
        self.ecosystem_type = "nodejs"

    def test_generate_report_json(self):
        report = generate_report_json(self.sample_dep_statuses, self.health_score, self.ecosystem_type)
        assert report['health_score'] == self.health_score
        assert report['project_type'] == self.ecosystem_type
        assert len(report['dependencies']) == 3
        assert len(report['recommendations']) == 2

    def test_generate_markdown_table_for_github(self):
        table = generate_markdown_table_for_github(self.sample_dep_statuses)
        assert "react" in table
        assert "lodash" in table
        assert "express" in table
        assert "🚨 Vulnerable" in table
        assert "⚠️ Outdated" in table
        assert "✅ Up-to-date" in table
        assert "CVE-2023-REACT" in table
        assert table.count('|---|') == 1
        assert table.count('`') > 0

class TestProjectDetection:
    def test_detect_nodejs_project(self, tmp_path):
        (tmp_path / "package.json").touch()
        with patch('os.getcwd', return_value=str(tmp_path)):
            assert detect_project_type() == "nodejs"

    def test_detect_python_project(self, tmp_path):
        (tmp_path / "requirements.txt").touch()
        with patch('os.getcwd', return_value=str(tmp_path)):
            assert detect_project_type() == "python"
    
    def test_detect_php_project(self, tmp_path):
        (tmp_path / "composer.json").touch()
        with patch('os.getcwd', return_value=str(tmp_path)):
            assert detect_project_type() == "php"

    def test_detect_no_project(self, tmp_path):
        with patch('os.getcwd', return_value=str(tmp_path)):
            assert detect_project_type() is None

class TestIgnoreFile:
    def test_read_ignore_file_basic(self, tmp_path):
        ignore_file = tmp_path / ".dephealthignore"
        ignore_file.write_text("package-a\n#comment\npackage-b\n")
        with patch('os.getcwd', return_value=str(tmp_path)):
            ignored = read_ignore_file()
            assert "package-a" in ignored
            assert "package-b" in ignored
            assert "#comment" not in ignored
            assert len(ignored) == 2

    def test_read_ignore_file_with_ecosystem_and_wildcard(self, tmp_path):
        ignore_file = tmp_path / ".dephealthignore"
        ignore_file.write_text("nodejs:express\npython:flask\n*-dev\ncommon-lib")
        
        with patch('os.getcwd', return_value=str(tmp_path)):
            nodejs_ignored = read_ignore_file(current_ecosystem="nodejs")
            assert "express" in nodejs_ignored
            assert "*-dev" in nodejs_ignored
            assert "common-lib" in nodejs_ignored
            assert "flask" not in nodejs_ignored # Should not include python-specific

            python_ignored = read_ignore_file(current_ecosystem="python")
            assert "flask" in python_ignored
            assert "*-dev" in python_ignored
            assert "common-lib" in python_ignored
            assert "express" not in python_ignored # Should not include nodejs-specific