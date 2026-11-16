# MasterAuditor

**A modular security auditing tool for Python projects.**

MasterAuditor is an open-source command-line tool designed to analyze Python codebases and identify potential security issues through static analysis.

Its modular architecture makes security checks extensible, maintainable, and easy to integrate into developer workflows.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features

- **Static Analysis** — Analyze Python source code using Abstract Syntax Trees (AST).
- **Security Rules** — Detect potentially unsafe coding practices and security vulnerabilities.
- **Modular Architecture** — Extensible rule system with a centralized registry and dedicated rules engine.
- **Structured Findings** — Report security issues with file locations, line numbers, and severity levels.
- **Severity Classification** — Categorize findings from informational to critical.
- **Command-Line Interface** — Run security audits directly from your terminal.

## Security Checks

MasterAuditor currently focuses on two main categories:

### Code Execution & Injection

Identifies potentially dangerous operations, including:

- Dynamic code execution (`eval`, `exec`, `compile`).
- Unsafe subprocess and shell usage.
- Operating system command execution.
- Potential SQL injection patterns.
- Dynamic imports.
- Unsafe deserialization and YAML loading.

### Hardcoded Credentials & Secrets

Detects potentially exposed sensitive information, including:

- Passwords and secret keys.
- API keys and access tokens.
- Client and refresh secrets.
- Private keys.
- Database credentials and connection strings.

## Requirements

- Python 3.11 or newer.

## Installation

Clone the repository:

```bash
git clone https://github.com/masteroid007/Master-Auditor.git
cd Master-Auditor
```

Create and activate a virtual environment:

```bash
python -m venv .venv
```

Install MasterAuditor:

```bash
python -m pip install -e .
```

## Usage

Display available commands and options:

```bash
maudit --help
```

Check the installed version:

```bash
maudit --version
```

Analyze a Python project:

```bash
maudit ./my-project
```

## Project Architecture

MasterAuditor follows a modular architecture built around four main components:

- **Scanner** — Discovers Python files in the target directory.
- **Analysis Engine** — Parses source files and extracts structural information through AST analysis.
- **Rules Engine** — Executes registered security rules against analyzed data.
- **Auditor** — Coordinates the scanning, analysis, and rule evaluation workflow.

This separation of responsibilities makes the project easier to extend and maintain.

## Contributing

Contributions, suggestions, and bug reports are welcome.

If you want to contribute, feel free to fork the repository and submit a pull request.

## Disclaimer

MasterAuditor is a static analysis tool intended to help identify potential security issues in Python projects.

Its findings should be reviewed by developers and security professionals. It does not guarantee the detection of every vulnerability.

## License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.