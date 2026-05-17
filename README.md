# pysecscan

[![tests](https://github.com/Cletus-FTL30/pysecscan/actions/workflows/test.yml/badge.svg)](https://github.com/Cletus-FTL30/pysecscan/actions/workflows/test.yml)

A CLI for catching committed secrets in a git repo, before they leak and after they have.

It catches:

- AWS access keys (`AKIA`, `ASIA`)
- GitHub tokens (classic `ghp_` and fine-grained `github_pat_`)
- Slack tokens and webhook URLs
- Stripe live secrets (`sk_live_`, `rk_live_`)
- JWTs
- Anything else with high enough entropy that it probably shouldn't be in source

Two modes. `scan` walks the working tree. `history` walks every blob that has ever existed in the repo's object database, which is where the worst leaks live: somebody committed a key, noticed an hour later, deleted the file, and pushed the "fix." The key is still right there in `git cat-file`.

## Install

```bash
git clone https://github.com/Cletus-FTL30/pysecscan.git
cd pysecscan
pip install -e .
```

Python 3.10 or newer.

## Usage

Scan the current directory:

```bash
pysecscan scan .
```

Scan a single file:

```bash
pysecscan scan path/to/something.py
```

Scan the whole git history:

```bash
pysecscan history .
```

Exit code is `0` if clean, `1` if anything matched, `2` if you pointed it at something invalid. That's the contract every pre-commit hook and CI step needs.

### Flags

`scan` mode:

```
--format text|json|sarif    output format (default: text)
--entropy-threshold 4.5     shannon threshold for the generic detector
--no-entropy                disable the entropy detector
--no-gitignore              ignore the repo's .gitignore
--exclude PATTERN           extra paths to skip, .gitignore syntax, repeatable
```

`history` mode supports `--format`, `--entropy-threshold`, and `--no-entropy`.

## How detection works

There are two layers, and they work better together than either alone.

The first layer is a small set of named regexes, one per known token format. These have basically no false positives because they're anchored to specific prefixes and lengths (an `AKIA` followed by exactly 16 base32 characters is, with very high probability, an actual AWS key). The catch is they only find secrets whose shape they already know.

The second layer is Shannon entropy. It scans every long enough run of base64-style characters and reports the ones with random-looking bit distributions. That picks up generic tokens, internal API keys, custom credential formats, anything that looks like a secret without needing a rule for it.

The entropy pass dedupes against the named rules, so a JWT (which both detectors would fire on) is only reported once, under the more specific name.

## Output

Text (default):

```
src/config.py:12: [aws-access-key-id] AKIAIOSFODNN7EXAMPLE

1 finding(s)
```

`--format json` gives a list of `{path, line, rule, match, blob}` objects. `--format sarif` produces SARIF 2.1.0, which uploads directly to GitHub code scanning.

## Pre-commit hook

Drop this into your `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/Cletus-FTL30/pysecscan
  rev: main
  hooks:
    - id: pysecscan
```

Then `pre-commit install`. From there, any commit that contains a secret in a staged file gets blocked locally before it ever reaches the remote.

## GitHub Action

For CI, add a step to your workflow:

```yaml
- uses: actions/checkout@v4
- uses: Cletus-FTL30/pysecscan@main
  with:
    path: .
    format: text
```

The action exits non-zero when findings are present, which fails the workflow and surfaces the issue on the PR.

## Development

```bash
git clone https://github.com/Cletus-FTL30/pysecscan.git
cd pysecscan
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Roadmap

PyPI release is next, after which the install step becomes a one-liner.

## License

MIT.
