# PySecScan

A CLI tool for scanning repositories for accidentally committed secrets  API keys, tokens, and passwords using regex pattern matching and Shannon entropy analysis.

## Features (in progress)

- `pysecscan scan <path>` — scan a directory for secrets
- Regex detection for AWS keys, GitHub PATs, Slack tokens, JWTs, and more
- Shannon entropy heuristic to reduce false positives
- Git history scanning
- JSON and SARIF output formats
- Pre-commit hook and GitHub Action integration

## Installation

```bash
pip install pysecscan
```

## Usage

```bash
pysecscan scan /path/to/repo
```

## Development

```bash
git clone https://github.com/your-username/pysecscan.git
cd pysecscan
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## License

MIT
