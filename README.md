# 🛡️ Dependency Health Dashboard CLI Tool

A lightweight, open-source command-line interface (CLI) tool to help open-source communities monitor and manage their project dependencies. This versatile tool analyzes your project's dependencies, identifies outdated or vulnerable packages, and provides a clear, actionable health report.

---

## ✨ Features

* **Multi-Ecosystem Support**: Automatically detects and scans dependencies for **Node.js** (`package.json`), **Python** (`requirements.txt`), and **PHP** (`composer.json`) projects. Easily extensible for more languages!
* **Accurate Version Checking**: Uses **semantic versioning** to correctly identify outdated packages, even with complex version strings (`^`, `~`, pre-releases).
* **Vulnerability Detection**: Integrates with ecosystem-specific audit tools:
    * `npm audit` for Node.js
    * `pip-audit` for Python
    * `composer audit` for PHP
* **Smart Health Score**: Calculates a simple, easy-to-understand health score (0-100) for your project's dependencies.
* **Actionable Recommendations**: Provides concrete steps to address outdated packages and security vulnerabilities.
* **Enhanced Output**: Displays clear, **colored reports** in your terminal, making critical issues easy to spot. Can also save them as a structured JSON file.
* **Efficient Performance**: Uses **in-memory caching** and **parallel API calls** to speed up scans, especially for large projects. A **progress bar** keeps you informed during the process.
* **Flexible Dependency Scope**: Option to scan only production dependencies, skipping development dependencies.
* **Advanced Dependency Filtering**: Ignore specific packages using a CLI flag or a powerful `.dephealthignore` file that supports patterns and per-ecosystem rules.
* **CI/CD Friendly Output**: Dedicated "quiet" and "JSON-only" modes for easy integration into automated pipelines.
* **GitHub Issue Integration (Optional)**: Automatically creates a new GitHub issue in your repository with the dependency health report, formatted as a readable **Markdown table**.
* **Health Badges**: Generate SVG and Markdown snippets for your project's health score badge, perfect for your `README.md`.
* **Self-Update Check**: A built-in command to check if a newer version of the CLI tool itself is available.
* **Internationalization (I18n)**: Supports localization for non-English users.

---

## 🚀 Getting Started

Follow these simple steps to get the Dependency Health Dashboard CLI tool up and running on your system.

### Step 1: Prerequisites

Before you begin, make sure you have the following installed on your computer:

* **Python 3.7 or newer**:
    * [Download Python](https://www.python.org/downloads/)
    * **Verify installation**: Open your terminal or command prompt and type `python3 --version` (or `python --version`). You should see a version number like `Python 3.9.7`.
* **Node.js and npm**: Required for scanning Node.js projects (`npm audit`).
    * [Download Node.js (which includes npm)](https://nodejs.org/en/download/)
    * **Verify installation**: In your terminal, type `node --version` and `npm --version`. You should see version numbers for both.
* **Python `pip-audit`**: Required for scanning Python projects.
    * Install it: `pip install pip-audit`
    * **Verify installation**: `pip-audit --version`
* **PHP and Composer**: Required for scanning PHP projects (`composer audit`).
    * [Install PHP](https://www.php.net/manual/en/install.php)
    * [Install Composer](https://getcomposer.org/download/)
    * **Verify installation**: `composer --version`

### Step 2: Download the Tool

You can get the tool by cloning its Git repository.

1.  **Open your terminal or command prompt.**
2.  **Navigate to a directory** where you want to store the tool (e.g., your `Documents` or `Projects` folder):
    ```bash
    cd ~/Documents/Projects
    ```
    (You can replace `~/Documents/Projects` with any path you prefer)
3.  **Clone the repository**:
    ```bash
    git clone [https://github.com/github.com/SmaRTy-Saini/DepHealth.git](https://github.com/SmaRTy-Saini/DepHealth.git)
    ```
 
4.  **Navigate into the tool's directory**:
    ```bash
    cd dependency-health-dashboard
    ```

### Step 3: Install Python Dependencies

The tool uses a few Python libraries that you need to install.

1.  While still in the `dependency-health-dashboard` directory (from Step 2.4), **install the required Python libraries**:
    ```bash
    pip install requests configparser packaging colorama tqdm
    ```
    * If you encounter issues, try `pip3 install requests configparser packaging colorama tqdm`.
    * `packaging` is used for accurate semantic version comparison.
    * `colorama` is used for colored terminal output.
    * `tqdm` is used for the progress bar during version fetching.

---

## 🌎 Internationalization (I18n)

The Dependency Health Dashboard supports multiple languages through `gettext`.

### How to use a different language:

Set the `LANG` environment variable before running the tool. For example, to run in French (if `fr` translations are available):

* **Linux/macOS**:
    ```bash
    export LANG=fr_FR.UTF-8
    python /path/to/dep_health.py scan
    ```
* **Windows (Command Prompt)**:
    ```cmd
    set LANG=fr_FR.UTF-8
    python /path/to/dep_health.py scan
    ```
* **Windows (PowerShell)**:
    ```powershell
    $env:LANG="fr_FR.UTF-8"
    python /path/to/dep_health.py scan
    ```

If the tool cannot find or load the translation files for your specified `LANG` environment variable, it will print a warning to help you troubleshoot your I18n setup (e.g., missing `.mo` file for the selected language).

### How to contribute new translations:

Community contributions for new languages are highly encouraged!

1.  **Generate a Portable Object (PO) template**:
    From the root of the `dependency-health-dashboard` directory:
    ```bash
    pygettext.py -D locale dep_health.py
    # This creates locale/dep_health.pot
    ```
2.  **Create a new language directory and initialize PO file**:
    For Spanish (`es`), for example:
    ```bash
    mkdir -p locale/es/LC_MESSAGES
    msginit --locale=es --input=locale/dep_health.pot --output-file=locale/es/LC_MESSAGES/dep_health.po
    ```
3.  **Translate**: Open `locale/es/LC_MESSAGES/dep_health.po` in a text editor (or a PO editor like [Poedit](https://poedit.net/)) and add your translations.
4.  **Compile to Machine Object (MO) file**:
    ```bash
    msgfmt locale/es/LC_MESSAGES/dep_health.po -o locale/es/LC_MESSAGES/dep_health.mo
    ```
5.  Commit both the `.po` and `.mo` files for your new language to the repository.

---

## 🚦 Usage

Once installed, you can use the tool by navigating to your project's root directory (where your manifest file like `package.json`, `requirements.txt`, or `composer.json` is located) and running the `dep_health.py` script.

### Check for Tool Updates

Before running a scan, it's good practice to check if you're using the latest version of the tool itself.

```bash
python /path/to/dependency-health-dashboard/dep_health.py update-check



## 📬 Connect with Me

- 💻 GitHub: [@SmaRTy-Saini](https://github.com/SmaRTy-Saini)
- 👔 LinkedIn: [smartysaini](https://www.linkedin.com/in/smartysaini/)
- 🛒 Gumroad Store: [smartysaini.gumroad.com](https://smartysaini.gumroad.com)
- 🐦 X (Twitter): [@SmaRTy__Saini](https://x.com/SmaRTy__Saini)

If this tool helped you, feel free to ⭐ star the repo or share it! Contributions welcome.
