import argparse
import json
import subprocess
import requests
import sys
import os
import configparser
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import gettext

# --- Internationalization Setup ---
LOCALE_DIR = Path(__file__).parent / "locale"
_current_locale_lang = os.getenv('LANG', 'en_US').split('.')[0]
try:
    _ = gettext.translation('dep_health', localedir=LOCALE_DIR, languages=[_current_locale_lang]).gettext
    _translation_loaded = True
except Exception:
    _ = lambda s: s
    _translation_loaded = False


# --- External Library Imports (with graceful degradation) ---
_colorama_warning = None
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    class NoColor:
        def __getattr__(self, name):
            return ''
    Fore = NoColor()
    Style = NoColor()
    _colorama_warning = _("Colorama not found. Install with 'pip install colorama' for colored output.")

_packaging_warning = None
try:
    from packaging.version import parse as parse_version
    VERSION_PARSE_ENABLED = True
except ImportError:
    VERSION_PARSE_ENABLED = False
    _packaging_warning = _("Packaging library not found. Install with 'pip install packaging' for accurate semantic versioning.")

_tqdm_warning = None
try:
    from tqdm import tqdm
    TQDM_ENABLED = True
except ImportError:
    TQDM_ENABLED = False
    _tqdm_warning = _("tqdm not found. Install with 'pip install tqdm' for progress indication.")


# --- Tool Metadata (for self-update and badge) ---
__version__ = "0.2.0"
# !!! IMPORTANT: REPLACE WITH YOUR ACTUAL GITHUB REPO URL !!!
TOOL_REPO_URL = "https://api.github.com/repos/your-username/dependency-health-dashboard"
TOOL_RELEASE_URL = "https://github.com/your-username/dependency-health-dashboard/releases/latest"

# --- Configuration Management ---
CONFIG_FILE = "config.ini"
NPM_REGISTRY_URL = "https://registry.npmjs.org/"
PYPI_REGISTRY_URL = "https://pypi.org/pypi/"
COMPOSER_REGISTRY_URL = "https://repo.packagist.org/packages/"

# Severity weights for health score calculation
SEVERITY_WEIGHTS = {
    "info": 0.1, "low": 0.2, "moderate": 0.4, "high": 0.7, "critical": 1.0
}
BASE_HEALTH_SCORE = 100
MAX_WORKER_THREADS = 8

# Cache for registry API calls during a single run
_VERSION_CACHE = {}

def load_config():
    """Loads configuration from config.ini."""
    config = configparser.ConfigParser()
    if Path(CONFIG_FILE).exists():
        config.read(CONFIG_FILE)
    return config

def get_github_token(config):
    """Gets GitHub token from environment variable or config."""
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    return config.get("github", "token", fallback=None)

# --- Helper Functions ---

def print_colored(text, color, style=None, file=sys.stdout):
    """Prints text with color if colorama is enabled."""
    if COLOR_ENABLED:
        if style:
            print(f"{style}{color}{text}{Style.RESET_ALL}", file=file)
        else:
            print(f"{color}{text}{Style.RESET_ALL}", file=file)
    else:
        print(text, file=file)

def log_warning(message, quiet=False):
    """Logs a warning message to stderr, respecting quiet mode."""
    if not quiet:
        print_colored(_("Warning:") + f" {message}", Fore.YELLOW, file=sys.stderr)

def log_error(message, quiet=False):
    """Logs an error message to stderr, respecting quiet mode."""
    if not quiet:
        print_colored(_("Error:") + f" {message}", Fore.RED, file=sys.stderr)

def get_severity_color(severity):
    """Returns colorama color based on severity level."""
    if not COLOR_ENABLED:
        return ''
    severity_lower = severity.lower()
    if severity_lower == "critical":
        return Fore.RED + Style.BRIGHT
    elif severity_lower == "high":
        return Fore.RED
    elif severity_lower == "moderate":
        return Fore.YELLOW
    elif severity_lower == "low":
        return Fore.CYAN
    elif severity_lower == "info":
        return Fore.BLUE
    else:
        return Fore.WHITE

def read_ignore_file(file_path=".dephealthignore", current_ecosystem=None):
    """
    Reads packages to ignore from .dephealthignore file.
    Supports ecosystem-specific rules (e.g., nodejs:package) and wildcards (*).
    """
    ignore_path = Path(file_path)
    if not ignore_path.exists():
        return set()
    
    ignored_packages = set()
    try:
        with ignore_path.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Handle ecosystem-specific rules
                if ':' in line:
                    ecosystem_prefix, pkg_pattern = line.split(':', 1)
                    if ecosystem_prefix == current_ecosystem:
                        ignored_packages.add(pkg_pattern.strip())
                else:
                    # General rule (applies to all ecosystems)
                    ignored_packages.add(line)
        
        # Expand wildcards (simple implementation, might need more robust fnmatch for complex cases)
        final_ignored = set()
        for pattern in ignored_packages:
            if '*' in pattern:
                # This is a very basic wildcard match. For production, consider `fnmatch`
                # and applying it against actual dependency names later in analyze_dependencies.
                # For now, we'll keep it simple for filtering before API calls.
                final_ignored.add(pattern) 
            else:
                final_ignored.add(pattern)
        
        return final_ignored
    except Exception as e:
        log_warning(_(f"Could not read .dephealthignore file: {e}. Skipping ignore list."))
        return set()

# --- Dependency Loading & Version Fetching ---

def load_package_json(file_path="package.json"):
    """Loads and parses the package.json file (Node.js)."""
    package_json_path = Path(file_path)
    if not package_json_path.exists():
        raise FileNotFoundError(_(f"'{file_path}' not found in the current directory."))
    try:
        with package_json_path.open('r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(_(f"Could not decode JSON from '{file_path}'. Please ensure it's a valid JSON file. Error: {e}"))
    except Exception as e:
        raise Exception(_(f"An unexpected error occurred while loading '{file_path}': {e}"))

def load_requirements_txt(file_path="requirements.txt"):
    """Loads and parses requirements.txt file (Python)."""
    req_path = Path(file_path)
    if not req_path.exists():
        raise FileNotFoundError(_(f"'{file_path}' not found in the current directory."))
    dependencies = {}
    try:
        with req_path.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                match = re.match(r"^([a-zA-Z0-9._-]+)(==|>=|<=|~=|>|<)?(.*)", line)
                if match:
                    pkg_name = match.group(1)
                    version_spec = match.group(3).split(',')[0].strip()
                    dependencies[pkg_name] = version_spec if version_spec else "latest"
        return {"dependencies": dependencies}
    except Exception as e:
        raise Exception(_(f"An unexpected error occurred while loading '{file_path}': {e}"))

def load_composer_json(file_path="composer.json"):
    """Loads and parses composer.json file (PHP)."""
    composer_path = Path(file_path)
    if not composer_path.exists():
        raise FileNotFoundError(_(f"'{file_path}' not found in the current directory."))
    try:
        with composer_path.open('r', encoding='utf-8') as f:
            data = json.load(f)
            deps = {**data.get("require", {}), **data.get("require-dev", {})}
            return {"dependencies": {k: v for k, v in deps.items() if not k.startswith("php") and not k.startswith("ext-")}}
    except json.JSONDecodeError as e:
        raise ValueError(_(f"Could not decode JSON from '{file_path}'. Please ensure it's a valid JSON file. Error: {e}"))
    except Exception as e:
        raise Exception(_(f"An unexpected error occurred while loading '{file_path}': {e}"))

# --- Version Fetchers (for parallelism) ---
def _fetch_latest_version_npm(package_name, quiet_mode):
    url = f"{NPM_REGISTRY_URL}{package_name}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        package_info = response.json()
        return package_info.get("dist-tags", {}).get("latest")
    except Exception as e:
        log_warning(_(f"Failed to fetch npm version for '{package_name}': {e}"), quiet_mode)
        return None

def _fetch_latest_version_pypi(package_name, quiet_mode):
    url = f"{PYPI_REGISTRY_URL}{package_name}/json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        package_info = response.json()
        return package_info.get("info", {}).get("version")
    except Exception as e:
        log_warning(_(f"Failed to fetch PyPI version for '{package_name}': {e}"), quiet_mode)
        return None

def _fetch_latest_version_composer(package_name, quiet_mode):
    url = f"{COMPOSER_REGISTRY_URL}{package_name}.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        package_info = response.get("packages", {}).get(package_name, {})
        if not package_info: # If package not found or no versions
            return None
        versions = package_info.keys()
        stable_versions = [v for v in versions if not re.search(r"[a-zA-Z]", v)]
        if not stable_versions:
            stable_versions = list(versions) # Fallback to any version if no stable
        
        if VERSION_PARSE_ENABLED:
            return str(max([parse_version(v) for v in stable_versions])) if stable_versions else None
        else:
            return max(stable_versions) if stable_versions else None

    except Exception as e:
        log_warning(_(f"Failed to fetch Composer version for '{package_name}': {e}"), quiet_mode)
        return None

def fetch_latest_versions_parallel(package_names_map, ecosystem_type, quiet_mode=False):
    """Fetches latest versions for a list of packages in parallel based on ecosystem."""
    results = {}
    fetch_func_map = {
        "nodejs": _fetch_latest_version_npm,
        "python": _fetch_latest_version_pypi,
        "php": _fetch_latest_version_composer,
    }
    fetch_func = fetch_func_map.get(ecosystem_type)
    if not fetch_func:
        log_warning(_(f"No version fetcher for ecosystem: {ecosystem_type}. Skipping version checks."), quiet_mode)
        return {name: _("N/A") for name in package_names_map.keys()}

    with ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS) as executor:
        future_to_package = {}
        for name in package_names_map.keys():
            if name in _VERSION_CACHE:
                results[name] = _VERSION_CACHE[name]
            else:
                future_to_package[executor.submit(fetch_func, name, quiet_mode)] = name
        
        if TQDM_ENABLED and not quiet_mode:
            iterator = tqdm(as_completed(future_to_package), total=len(future_to_package), desc=_("Fetching latest versions"), unit=_("pkg"))
        else:
            iterator = as_completed(future_to_package)

        for future in iterator:
            pkg_name = future_to_package[future]
            try:
                latest_version = future.result()
                _VERSION_CACHE[pkg_name] = latest_version
                results[pkg_name] = latest_version
            except Exception as e:
                log_warning(_(f"Error fetching version for {pkg_name}: {e}"), quiet_mode)
                _VERSION_CACHE[pkg_name] = None
                results[pkg_name] = None
    return results

# --- Vulnerability Audits ---

def run_npm_audit_command(quiet_mode=False):
    """Runs npm audit and returns the parsed JSON output."""
    try:
        process = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8',
            errors='replace'
        )

        if process.returncode not in [0, 1]:
            log_warning(_(f"'npm audit' exited with an unexpected code {process.returncode}. Output: {process.stderr.strip()}"), quiet_mode)
            return {"auditReportVersion": 2, "vulnerabilities": {}}
        
        if not process.stdout.strip():
            log_warning(_("'npm audit' returned no output. Is npm installed and configured correctly in your project?"), quiet_mode)
            return {"auditReportVersion": 2, "vulnerabilities": {}}

        try:
            audit_result = json.loads(process.stdout)
            return audit_result
        except json.JSONDecodeError as e:
            log_error(_(f"Could not decode JSON from 'npm audit' output. Raw output (first 500 chars): {process.stdout[:500]}. Error: {e}"), quiet_mode)
            return {"auditReportVersion": 2, "vulnerabilities": {}}

    except FileNotFoundError:
        raise RuntimeError(_("'npm' command not found. Please ensure Node.js and npm are installed and in your system's PATH."))
    except Exception as e:
        log_error(_(f"An unexpected error occurred during 'npm audit': {e}"), quiet_mode)
        return None

def run_pip_audit_command(quiet_mode=False):
    """Runs pip-audit and returns the parsed JSON output."""
    try:
        process = subprocess.run(
            ["pip-audit", "--json", "--isolated"],
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8',
            errors='replace'
        )

        if process.returncode not in [0, 1]:
            log_warning(_(f"'pip-audit' exited with an unexpected code {process.returncode}. Output: {process.stderr.strip()}"), quiet_mode)
            return {"vulnerabilities": []}
        
        if not process.stdout.strip():
            log_warning(_("'pip-audit' returned no output. Are dependencies installed in a virtual environment?"), quiet_mode)
            return {"vulnerabilities": []}

        try:
            audit_result = json.loads(process.stdout)
            vulnerabilities_map = {}
            for vuln in audit_result:
                package_name = vuln['package']['name']
                vulnerabilities_map.setdefault(package_name, {
                    "name": package_name,
                    "severity": vuln['id'].split('-')[0].lower() if '-' in vuln['id'] else "moderate",
                    "via": [],
                    "fixAvailable": False,
                    "title": vuln['advisory']['title']
                })
                vulnerabilities_map[package_name]["via"].append({
                    "cve": vuln['advisory']['cve_id'] if vuln['advisory']['cve_id'] else vuln['id'],
                    "severity": vuln['id'].split('-')[0].lower() if '-' in vuln['id'] else "moderate",
                    "url": vuln['advisory']['link']
                })
            return {"vulnerabilities": vulnerabilities_map}
        except json.JSONDecodeError as e:
            log_error(_(f"Could not decode JSON from 'pip-audit' output. Raw output (first 500 chars): {process.stdout[:500]}. Error: {e}"), quiet_mode)
            return {"vulnerabilities": []}

    except FileNotFoundError:
        raise RuntimeError(_("'pip-audit' command not found. Install it with 'pip install pip-audit' and ensure it's in your PATH."))
    except Exception as e:
        log_error(_(f"An unexpected error occurred during 'pip-audit': {e}"), quiet_mode)
        return None

def run_composer_audit_command(quiet_mode=False):
    """Runs composer audit and returns the parsed JSON output."""
    try:
        if not Path("composer.lock").exists():
            log_warning(_("composer.lock not found. Running `composer install --no-dev` to generate it for audit."), quiet_mode)
            # This is a critical step for Composer audit, potentially long-running
            install_process = subprocess.run(
                ["composer", "install", "--no-dev", "--no-interaction"], 
                capture_output=True, check=False, encoding='utf-8', errors='replace',
                cwd=os.getcwd() # Ensure it runs in the current project dir
            )
            if install_process.returncode != 0:
                log_warning(_(f"Composer install failed, audit might be incomplete: {install_process.stderr.strip()}"), quiet_mode)


        process = subprocess.run(
            ["composer", "audit", "--format=json", "--no-dev"],
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8',
            errors='replace'
        )

        if process.returncode not in [0, 1]:
            log_warning(_(f"'composer audit' exited with an unexpected code {process.returncode}. Output: {process.stderr.strip()}"), quiet_mode)
            return {"vulnerabilities": {}}
        
        if not process.stdout.strip():
            log_warning(_("'composer audit' returned no output. Are dependencies installed?"), quiet_mode)
            return {"vulnerabilities": {}}

        try:
            audit_result = json.loads(process.stdout)
            vulnerabilities_map = {}
            for vuln in audit_result:
                package_name = vuln['package']
                vulnerabilities_map.setdefault(package_name, {
                    "name": package_name,
                    "severity": vuln['advisory']['severity'].lower() if 'severity' in vuln['advisory'] else "moderate",
                    "via": [],
                    "fixAvailable": False,
                    "title": vuln['advisory']['title']
                })
                vulnerabilities_map[package_name]["via"].append({
                    "cve": vuln['advisory'].get('cve', vuln['advisory'].get('id', _('N/A'))),
                    "severity": vuln['advisory'].get('severity', 'moderate').lower(),
                    "url": vuln['advisory']['link']
                })
            return {"vulnerabilities": vulnerabilities_map}
        except json.JSONDecodeError as e:
            log_error(_(f"Could not decode JSON from 'composer audit' output. Raw output (first 500 chars): {process.stdout[:500]}. Error: {e}"), quiet_mode)
            return {"vulnerabilities": {}}

    except FileNotFoundError:
        raise RuntimeError(_("'composer' command not found. Please ensure Composer is installed and in your PATH."))
    except Exception as e:
        log_error(_(f"An unexpected error occurred during 'composer audit': {e}"), quiet_mode)
        return None


def run_audit_command(ecosystem_type, quiet_mode=False):
    """Dispatches to the appropriate audit command for the given ecosystem."""
    if ecosystem_type == "nodejs":
        return run_npm_audit_command(quiet_mode)
    elif ecosystem_type == "python":
        return run_pip_audit_command(quiet_mode)
    elif ecosystem_type == "php":
        return run_composer_audit_command(quiet_mode)
    log_warning(_(f"No audit command implemented for ecosystem: {ecosystem_type}. Skipping vulnerability checks."), quiet_mode)
    return {"vulnerabilities": {}}

# --- Core Analysis Logic ---

def analyze_dependencies(package_data, ecosystem_type, prod_only=False, ignore_packages=None, quiet_mode=False):
    """
    Analyzes dependencies for outdated versions and vulnerabilities for a given ecosystem.
    Args:
        package_data (dict): Parsed content of manifest file.
        ecosystem_type (str): Type of ecosystem (e.js., 'nodejs', 'python', 'php').
        prod_only (bool): If True, only scan production dependencies.
        ignore_packages (set): Set of package patterns to ignore.
        quiet_mode (bool): Suppress non-essential output.
    Returns:
        tuple: (list of dependency statuses, outdated count, total vulnerability score, total dependencies)
    """
    if ignore_packages is None:
        ignore_packages = set()

    dependencies_to_scan = package_data.get("dependencies", {})
    if ecosystem_type == "nodejs" and not prod_only:
        dev_dependencies = package_data.get("devDependencies", {})
        dependencies_to_scan = {**dependencies_to_scan, **dev_dependencies}
    elif ecosystem_type == "php":
         if prod_only:
             dependencies_to_scan = package_data.get("require", {})
         else:
             pass # Composer's 'require' and 'require-dev' combined in load_composer_json by default


    # Apply ignore patterns (simple wildcard match)
    filtered_dependencies = {}
    for name, version in dependencies_to_scan.items():
        should_ignore = False
        for ignore_pattern in ignore_packages:
            if '*' in ignore_pattern:
                if re.fullmatch(ignore_pattern.replace('*', '.*'), name):
                    should_ignore = True
                    break
            elif name == ignore_pattern:
                should_ignore = True
                break
        if not should_ignore:
            filtered_dependencies[name] = version
    
    dependencies_to_scan = filtered_dependencies


    dependency_statuses = []
    outdated_count = 0
    total_vulnerability_score = 0
    vulnerable_packages_map = {}

    if not quiet_mode:
        print_colored(_(f"\nScanning dependencies for {ecosystem_type} project..."), Fore.CYAN)

    audit_results = run_audit_command(ecosystem_type, quiet_mode)

    if audit_results and "vulnerabilities" in audit_results:
        vulnerabilities_data = audit_results.get("vulnerabilities", {})

        for pkg_name, pkg_data in vulnerabilities_data.items():
            if pkg_name not in dependencies_to_scan: # Check against filtered list
                continue

            highest_severity_for_package = "info"
            cve_list = []
            
            if isinstance(pkg_data.get('via'), list):
                for advisory_info in pkg_data.get("via", []):
                    if isinstance(advisory_info, dict):
                        if advisory_info.get('cve') and advisory_info['cve'] not in cve_list:
                            cve_list.append(advisory_info['cve'])
                        
                        severity = advisory_info.get('severity', 'info').lower()
                        if SEVERITY_WEIGHTS.get(severity, 0) > SEVERITY_WEIGHTS.get(highest_severity_for_package, 0):
                            highest_severity_for_package = severity
            else:
                severity = pkg_data.get('severity', 'info').lower()
                if SEVERITY_WEIGHTS.get(severity, 0) > SEVERITY_WEIGHTS.get(highest_severity_for_package, 0):
                    highest_severity_for_package = severity
                if pkg_data.get('cve') and pkg_data['cve'] != _('N/A') and pkg_data['cve'] not in cve_list:
                    cve_list.append(pkg_data['cve'])

            vulnerable_packages_map[pkg_name] = {
                "severity": highest_severity_for_package,
                "cve": ", ".join(cve_list) if cve_list else _("N/A"),
                "recommendation": pkg_data.get("fixAvailable", False),
                "overview": pkg_data.get("title", _("No specific details provided by audit."))
            }
            total_vulnerability_score += SEVERITY_WEIGHTS.get(highest_severity_for_package, 0)

    latest_versions_map = fetch_latest_versions_parallel(dependencies_to_scan, ecosystem_type, quiet_mode)

    for dep_name, current_version_raw in dependencies_to_scan.items():
        current_version_clean = current_version_raw.lstrip('^~<=> ')
        
        latest_version = latest_versions_map.get(dep_name)
        
        is_outdated = False
        if latest_version and current_version_clean and latest_version != _("N/A"):
            try:
                if VERSION_PARSE_ENABLED:
                    parsed_current = parse_version(current_version_clean)
                    parsed_latest = parse_version(latest_version)
                    if parsed_latest > parsed_current:
                        is_outdated = True
                        outdated_count += 1
                else:
                    log_warning(_("Packaging library not found for accurate semantic versioning. Using simple comparison for '{dep_name}'."), quiet_mode)
                    if latest_version != current_version_clean:
                        is_outdated = True
                        outdated_count += 1
            except Exception as e:
                log_warning(_(f"Could not parse version for '{dep_name}' ({current_version_clean} vs {latest_version}): {e}. Using simple comparison."), quiet_mode)
                if latest_version != current_version_clean:
                    is_outdated = True
                    outdated_count += 1
        
        vulnerability_info = vulnerable_packages_map.get(dep_name, {
            "severity": _("N/A"), "cve": _("N/A"), "recommendation": False, "overview": _("No known vulnerabilities.")
        })
        
        dependency_statuses.append({
            "name": dep_name,
            "current_version": current_version_clean,
            "latest_version": latest_version if latest_version else _("N/A"),
            "is_outdated": is_outdated,
            "vulnerable": bool(vulnerable_packages_map.get(dep_name)),
            "vulnerability_severity": vulnerability_info["severity"],
            "vulnerability_cve": vulnerability_info["cve"],
            "vulnerability_fix_available": vulnerability_info["recommendation"],
            "vulnerability_overview": vulnerability_info["overview"]
        })
    
    return dependency_statuses, outdated_count, total_vulnerability_score, len(dependencies_to_scan)

# --- Report Generation ---

def generate_report_text(dependency_statuses, health_score, ecosystem_type, quiet_mode=False):
    """Generates the plain text report for console output with colors."""
    report_lines = ["", _("Dependency Health Report"), "=" * 26]
    report_lines.append(_(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    report_lines.append(_(f"Project Type: {ecosystem_type.capitalize()}"))
    
    health_color = Fore.GREEN if health_score >= 80 else (Fore.YELLOW if health_score >= 50 else Fore.RED)
    report_lines.append(_(f"Health Score: {health_color}{health_score}/100{Style.RESET_ALL}\n"))
    
    report_lines.append(_("Dependencies:"))

    recommendations = []
    
    sorted_deps = sorted(dependency_statuses, key=lambda x: (
        -SEVERITY_WEIGHTS.get(x['vulnerability_severity'].lower(), 0),
        1 if x['is_outdated'] and not x['vulnerable'] else 0,
        x['name'].lower()
    ))

    for dep in sorted_deps:
        line_color = Fore.GREEN
        
        status_parts = [_(f"- {Fore.WHITE}{Style.BRIGHT}{dep['name']}{Style.RESET_ALL}: v{dep['current_version']}")]
        
        if dep['latest_version'] != _("N/A"):
            status_parts.append(_(f"(Latest: v{dep['latest_version']}"))
        else:
            status_parts.append(_("(Latest: N/A"))

        vulnerability_text = ""
        if dep['vulnerable']:
            line_color = get_severity_color(dep['vulnerability_severity'])
            cve_info = _(f"CVE: {dep['vulnerability_cve']}") if dep['vulnerability_cve'] != _('N/A') else dep['vulnerability_overview']
            vulnerability_text = _(f" | {line_color}Vulnerable:{Style.RESET_ALL} {cve_info}, {line_color}Severity: {dep['vulnerability_severity'].capitalize()}{Style.RESET_ALL}")
            if dep['vulnerability_fix_available']:
                vulnerability_text += _(f" {Fore.CYAN}(Fix available){Style.RESET_ALL}")
            status_parts.append(vulnerability_text + ")")

            rec_text = _(f"{line_color}Fix {dep['name']}:{Style.RESET_ALL} {dep['vulnerability_overview']} (CVE: {dep['vulnerability_cve'] if dep['vulnerability_cve'] != _('N/A') else _('N/A')}, Severity: {dep['vulnerability_severity'].capitalize()})")
            if dep['vulnerability_fix_available']:
                rec_text += _(f" - {Fore.CYAN}Update recommended.{Style.RESET_ALL}")
            recommendations.append(rec_text)
        elif dep['is_outdated']:
            line_color = Fore.YELLOW
            status_parts.append(")")
            recommendations.append(_(f"{Fore.YELLOW}Update {dep['name']}:{Style.RESET_ALL} to v{dep['latest_version']} for latest features and security patches."))
        else:
            status_parts.append(_(" | No known issues)"))
            line_color = Fore.GREEN

        report_lines.append(f"{line_color}{''.join(status_parts)}{Style.RESET_ALL}")

    report_lines.append(_("\nRecommendations:"))
    if not recommendations:
        report_lines.append(_(f"{Fore.GREEN}No immediate actions recommended. Your dependencies look healthy!{Style.RESET_ALL}"))
    else:
        unique_recommendations = sorted(list(set(recommendations)), key=lambda x: (
            "Fix" not in x,
            x
        ))
        for i, reco in enumerate(unique_recommendations[:5]):
            report_lines.append(f"{i+1}. {reco}")
    
    report_lines.append(_("\nTo save this report, use: `python dep_health.py scan --output report.json`"))
    report_lines.append(_("For more options, run: `python dep_health.py --help`"))
    return "\n".join(report_lines)

def generate_report_json(dependency_statuses, health_score, ecosystem_type):
    """Generates the JSON report for file output."""
    json_output = {
        "scan_date": datetime.now().isoformat(),
        "project_type": ecosystem_type,
        "health_score": health_score,
        "dependencies": [
            {
                "name": dep["name"],
                "current_version": dep["current_version"],
                "latest_version": dep["latest_version"],
                "is_outdated": dep["is_outdated"],
                "vulnerable": dep["vulnerable"],
                "vulnerability_details": {
                    "severity": dep["vulnerability_severity"],
                    "cve": dep["vulnerability_cve"],
                    "fix_available": dep["vulnerability_fix_available"],
                    "overview": dep["vulnerability_overview"]
                } if dep["vulnerable"] else None
            } for dep in dependency_statuses
        ],
        "recommendations": []
    }
    
    recommendations_set = set()
    for dep in dependency_statuses:
        if dep['vulnerable']:
            rec_text = _(f"Fix {dep['name']}: {dep['vulnerability_overview']} (CVE: {dep['vulnerability_cve']}, Severity: {dep['vulnerability_severity'].capitalize()})")
            if dep['vulnerability_fix_available']:
                rec_text += _(" - Update recommended.")
            recommendations_set.add(rec_text)
        elif dep['is_outdated']:
            recommendations_set.add(_(f"Update {dep['name']} to v{dep['latest_version']} for latest features and security patches."))
    
    json_output["recommendations"] = sorted(list(recommendations_set))

    return json_output

def generate_markdown_table_for_github(dependency_statuses):
    """Generates a Markdown table for dependencies suitable for GitHub issues."""
    if not dependency_statuses:
        return _("No dependencies found or analyzed.")

    headers = [_("Dependency"), _("Current"), _("Latest"), _("Status"), _("Vulnerability Info")]
    table_lines = ["| " + " | ".join(headers) + " |", "|---|---|---|---|---|"]

    sorted_deps = sorted(dependency_statuses, key=lambda x: (
        -SEVERITY_WEIGHTS.get(x['vulnerability_severity'].lower(), 0),
        1 if x['is_outdated'] and not x['vulnerable'] else 0,
        x['name'].lower()
    ))

    for dep in sorted_deps:
        status = "✅ " + _("Up-to-date")
        vulnerability_info = _("N/A")

        if dep['vulnerable']:
            status = "🚨 " + _("Vulnerable")
            cve_part = _(f"({dep['vulnerability_cve']})") if dep['vulnerability_cve'] != _('N/A') else ''
            fix_part = _("(Fix Available)") if dep['vulnerability_fix_available'] else ""
            vulnerability_info = _(f"{dep['vulnerability_severity'].capitalize()}: {dep['vulnerability_overview']} {cve_part} {fix_part}")
        elif dep['is_outdated']:
            status = "⚠️ " + _("Outdated")

        row = [
            f"`{dep['name']}`",
            f"`v{dep['current_version']}`",
            f"`v{dep['latest_version']}`" if dep['latest_version'] != _('N/A') else _("N/A"),
            status,
            vulnerability_info
        ]
        table_lines.append("| " + " | ".join(row) + " |")
    
    return "\n".join(table_lines)


# --- GitHub Integration & Badges ---

def create_github_issue(report_content_json, github_token, repo_owner, repo_name, quiet_mode=False):
    """Creates a GitHub issue with the dependency health report."""
    if not github_token:
        log_error(_("GitHub token is not provided. Set GITHUB_TOKEN environment variable or configure 'config.ini'."), quiet_mode)
        return

    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues"
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    title = _(f"Dependency Health Report: Action Required - {report_content_json['scan_date'][:10]} ({report_content_json['project_type'].capitalize()} Project)")
    
    markdown_table = generate_markdown_table_for_github(report_content_json['dependencies'])
    
    body = (
        _(f"## Dependency Health Dashboard Report - {report_content_json['scan_date'][:10]} ({report_content_json['project_type'].capitalize()})\n\n")
        + _(f"**Overall Health Score**: {report_content_json['health_score']}/100\n\n")
        + _(f"### Summary of Dependencies:\n")
        + f"{markdown_table}\n\n"
        + _(f"### Recommendations:\n")
    )
    if report_content_json['recommendations']:
        for i, reco in enumerate(report_content_json['recommendations']):
            body += f"{i+1}. {reco}\n"
    else:
        body += _("No immediate actions recommended. Your dependencies look healthy!\n")
    
    body += (
        _("\n---\n")
        + _(f"This issue was automatically generated by the [Dependency Health Dashboard CLI tool]({TOOL_RELEASE_URL}) ")
        + _("to highlight potential dependency issues. Please address the recommended actions.\n")
        + _("\n**Raw Report (for detailed view):**\n")
        + f"```json\n{json.dumps(report_content_json, indent=2)}\n```\n"
    )

    data = {
        "title": title,
        "body": body,
        "labels": ["dependency-health", "security", "bug"]
    }

    try:
        if not quiet_mode:
            print_colored(_(f"Attempting to create GitHub issue in {repo_owner}/{repo_name}..."), Fore.CYAN)
        response = requests.post(url, headers=headers, json=data, timeout=15)
        response.raise_for_status()
        if not quiet_mode:
            print_colored(_(f"✅ Successfully created GitHub issue: {response.json().get('html_url')}"), Fore.GREEN)
    except requests.exceptions.HTTPError as e:
        log_error(_(f"Error creating GitHub issue (HTTP {e.response.status_code}): {e}"), quiet_mode)
        if e.response.status_code == 404:
            log_warning(_("  Reason: Repository not found or incorrect owner/name. Please check --repo-owner and --repo-name."), quiet_mode)
        elif e.response.status_code == 401:
            log_warning(_("  Reason: Unauthorized. Please check if your GITHUB_TOKEN is valid and has 'repo' scope."), quiet_mode)
        elif e.response.status_code == 403:
             log_warning(_(f"  Reason: Forbidden. Likely API rate limit or insufficient permissions. {e.response.json().get('message', '')}"), quiet_mode)
        else:
            log_warning(_(f"  GitHub API response: {e.response.json().get('message', 'No specific error message.')}"), quiet_mode)
    except requests.exceptions.ConnectionError:
        log_error(_("Network connection problem while trying to reach GitHub API. Check your internet connection."), quiet_mode)
    except requests.exceptions.Timeout:
        log_error(_("Request to GitHub API timed out. The server might be busy or your connection is slow."), quiet_mode)
    except Exception as e:
        log_error(_(f"An unexpected error occurred while creating GitHub issue: {e}"), quiet_mode)

def get_badge_color_from_score(score):
    """Maps health score to a badge color for Shields.io."""
    if score >= 90: return "brightgreen"
    elif score >= 70: return "green"
    elif score >= 50: return "yellowgreen"
    elif score >= 30: return "orange"
    else: return "red"

def generate_health_badge(health_score, quiet_mode=False):
    """Generates a Shields.io compatible SVG badge URL and Markdown for the health score."""
    label = _("dependency health")
    message = f"{health_score}%"
    color = get_badge_color_from_score(health_score)
    
    badge_url = f"https://img.shields.io/badge/{label.replace(' ', '%20')}-{message}-{color}?style=flat-square"
    markdown_badge = f"![{label}]({badge_url})"
    
    if not quiet_mode:
        print_colored(_(f"\nGenerated Health Badge URL:\n{Fore.CYAN}{badge_url}{Style.RESET_ALL}"), Fore.BLUE)
        print_colored(_(f"\nGenerated Health Badge Markdown (for README):\n{Fore.CYAN}{markdown_badge}{Style.RESET_ALL}"), Fore.BLUE)
    
    return badge_url, markdown_badge

# --- Self-Update Logic ---
def check_for_updates(quiet_mode=False):
    """Checks for a new version of the CLI tool on GitHub."""
    if not quiet_mode:
        print_colored(_("Checking for tool updates..."), Fore.CYAN)
    try:
        response = requests.get(f"{TOOL_REPO_URL}/releases/latest", timeout=10)
        response.raise_for_status()
        latest_release_info = response.json()
        
        latest_version_tag = latest_release_info.get("tag_name", "").lstrip("vV")
        
        if not latest_version_tag:
            log_warning(_("Could not determine latest version from GitHub releases."), quiet_mode)
            return False
        
        current_version_parsed = parse_version(__version__)
        latest_version_parsed = parse_version(latest_version_tag)

        if latest_version_parsed > current_version_parsed:
            if not quiet_mode:
                print_colored(_(f"A new version is available: {Fore.YELLOW}v{latest_version_tag}{Style.RESET_ALL} (Current: v{__version__})"), Fore.YELLOW, Style.BRIGHT)
                print_colored(_("Please update your tool by running: "), Fore.YELLOW)
                print_colored(_("  git pull origin main"), Fore.YELLOW, Style.BRIGHT)
                print_colored(_(f"Or download from: {TOOL_RELEASE_URL}"), Fore.YELLOW)
            return True
        else:
            if not quiet_mode:
                print_colored(_(f"You are running the latest version: v{__version__}"), Fore.GREEN)
            return False
    except requests.exceptions.RequestException as e:
        log_error(_(f"Could not check for updates (network or API error): {e}"), quiet_mode)
        return False
    except Exception as e:
        log_error(_(f"An unexpected error occurred during update check: {e}"), quiet_mode)
        return False

# --- Main CLI Logic ---
def main():
    config = load_config()

    parser = argparse.ArgumentParser(
        description=_("Dependency Health Dashboard CLI tool. Analyze dependencies, identify vulnerabilities, and generate reports."),
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help=_("Available commands"), required=True)

    # 'scan' command
    scan_parser = subparsers.add_parser(
        "scan",
        help=_("Scan your project's dependencies for health."),
        description=_("Scans project dependencies, checks for outdated versions and vulnerabilities, and generates a comprehensive report.\n"
                      "Automatically detects project type (Node.js, Python, PHP) based on manifest files.")
    )
    scan_parser.add_argument(
        "--output",
        help=_("Optional: Path to save the report as a JSON file (e.g., 'report.json').")
    )
    scan_parser.add_argument(
        "--github",
        action="store_true",
        help=_("Optional: Create a GitHub issue with the report. Requires GITHUB_TOKEN env var or config.ini, --repo-owner, and --repo-name.")
    )
    scan_parser.add_argument(
        "--repo-owner",
        default=config.get("github", "repo_owner", fallback=None),
        help=_("GitHub repository owner (e.g., 'octocat'). Can also be set in config.ini.")
    )
    scan_parser.add_argument(
        "--repo-name",
        default=config.get("github", "repo_name", fallback=None),
        help=_("GitHub repository name (e.g., 'Spoon-Knife'). Can also be set in config.ini.")
    )
    scan_parser.add_argument(
        "--prod-only",
        action="store_true",
        help=_("Optional: Only scan production dependencies (skip 'devDependencies' for Node.js, 'require-dev' for PHP).")
    )
    scan_parser.add_argument(
        "--ignore",
        help=_("Optional: Comma-separated list of package names to ignore from scan and vulnerability checks (e.g., 'package-a,package-b').")
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help=_("Optional: Suppress most terminal output, only show final report or errors.")
    )
    scan_parser.add_argument(
        "--json-only",
        action="store_true",
        help=_("Optional: Output only the JSON report to stdout, suppressing all other terminal output. Ideal for CI/CD piping.")
    )
    scan_parser.add_argument(
        "--generate-badge",
        action="store_true",
        help=_("Optional: Generate a health score badge URL and Markdown for your README.")
    )

    # 'update-check' command
    update_parser = subparsers.add_parser(
        "update-check",
        help=_("Check if a new version of the Dependency Health Dashboard CLI tool is available."),
        description=_("Connects to the GitHub repository to see if a newer release of the tool exists.")
    )
    update_parser.add_argument(
        "--quiet",
        action="store_true",
        help=_("Optional: Suppress most terminal output for update check.")
    )


    args = parser.parse_args()

    # Determine output mode
    quiet_mode = args.quiet or args.json_only
    json_only_mode = args.json_only

    # Print initial library import warnings if not in quiet/json_only mode
    if not quiet_mode:
        if not _translation_loaded and _current_locale_lang != 'en':
            print_colored(_(f"Warning: Could not load translations for '{_current_locale_lang}'. Defaulting to English. Ensure 'locale/{_current_locale_lang}/LC_MESSAGES/dep_health.mo' exists."), Fore.YELLOW, file=sys.stderr)
        if _colorama_warning:
            print_colored(_colorama_warning, Fore.YELLOW, file=sys.stderr)
        if _packaging_warning:
            print_colored(_packaging_warning, Fore.YELLOW, file=sys.stderr)
        if _tqdm_warning:
            print_colored(_tqdm_warning, Fore.YELLOW, file=sys.stderr)


    if args.command == "scan":
        if not json_only_mode:
            print_colored(_("🚀 Starting Dependency Health Scan..."), Fore.CYAN, Style.BRIGHT)
        
        project_type = detect_project_type()
        if not project_type:
            log_error(_("No recognized project file found (e.g., 'package.json', 'requirements.txt', 'composer.json') in the current directory."), quiet_mode)
            sys.exit(1)
        
        ignored_packages_raw = set()
        if args.ignore:
            ignored_packages_raw.update(pkg.strip() for pkg in args.ignore.split(','))
        
        # Read .dephealthignore based on current project type
        ignored_packages_from_file = read_ignore_file(current_ecosystem=project_type)
        ignored_packages_raw.update(ignored_packages_from_file)


        try:
            package_data = {}
            if project_type == "nodejs":
                package_data = load_package_json()
            elif project_type == "python":
                package_data = load_requirements_txt()
            elif project_type == "php":
                package_data = load_composer_json()

            dependency_statuses, outdated_count, total_vulnerability_score, total_dependencies = \
                analyze_dependencies(package_data, project_type, args.prod_only, ignored_packages_raw, quiet_mode)
            
            health_score = calculate_health_score(outdated_count, total_vulnerability_score, total_dependencies)
            
            json_report_content = generate_report_json(dependency_statuses, health_score, project_type)

            if json_only_mode:
                print(json.dumps(json_report_content, indent=2))
                sys.exit(0)

            text_report_content = generate_report_text(dependency_statuses, health_score, project_type, quiet_mode)
            print(text_report_content)

            if args.output:
                try:
                    with Path(args.output).open('w', encoding='utf-8') as f:
                        json.dump(json_report_content, f, indent=2)
                    if not quiet_mode:
                        print_colored(_(f"\n✅ Report successfully saved to '{args.output}'"), Fore.GREEN)
                except IOError as e:
                    log_error(_(f"Could not write report to '{args.output}': {e}"), quiet_mode)
                except Exception as e:
                    log_error(_(f"An unexpected error occurred while saving report: {e}"), quiet_mode)

            if args.github:
                repo_owner = args.repo_owner
                repo_name = args.repo_name
                github_token = get_github_token(config)

                if not repo_owner or not repo_name:
                    log_error(_("\n🛑 Error: '--repo-owner' and '--repo-name' are required for GitHub integration, or set them in config.ini."), quiet_mode)
                elif not github_token:
                    log_error(_("\n🛑 Error: GitHub Personal Access Token (GITHUB_TOKEN) not found. Set it as an environment variable or in config.ini."), quiet_mode)
                else:
                    create_github_issue(json_report_content, github_token, repo_owner, repo_name, quiet_mode)
            
            if args.generate_badge:
                generate_health_badge(health_score, quiet_mode)

        except (FileNotFoundError, ValueError, RuntimeError) as e:
            log_error(_(f"\n❌ Scan failed: {e}"), quiet_mode)
            sys.exit(1)
        except Exception as e:
            log_error(_(f"\n❌ An unexpected fatal error occurred during scan: {e}"), quiet_mode)
            sys.exit(1)
    
    elif args.command == "update-check":
        check_for_updates(args.quiet)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()