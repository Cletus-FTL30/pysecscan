import argparse
import json
import sys
from pathlib import Path

from pysecscan import __version__
from pysecscan.detectors import DEFAULT_ENTROPY, Finding, scan_file, scan_text
from pysecscan.history import is_git_repo, iter_blobs, read_blob
from pysecscan.walker import walk


def _to_sarif(findings, root):
    # SARIF 2.1.0. this is the bare-minimum shape GitHub code-scanning will
    # accept on upload; locations + ruleId + message are the only fields it
    # actually surfaces in the UI.
    def _rel(p):
        # SARIF URIs are conventionally relative to the run's source root.
        # fall back to absolute if the path isn't under root for any reason.
        try:
            return str(Path(p).resolve().relative_to(Path(root).resolve()))
        except ValueError:
            return str(p)

    def _result(h):
        r = {
            "ruleId": h.rule,
            # everything we detect is treated as an error. severity tiers
            # can come later when rules grow categories.
            "level": "error",
            "message": {"text": f"{h.rule} match: {h.match}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _rel(h.path)},
                        "region": {"startLine": h.line},
                    }
                }
            ],
        }
        # blob SHA only relevant for history-mode findings. tucked under
        # properties so it doesn't trip strict SARIF consumers.
        if h.blob:
            r["properties"] = {"blob": h.blob}
        return r

    rules_seen = sorted({h.rule for h in findings})
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pysecscan",
                        "version": __version__,
                        "informationUri": "https://github.com/ebukacletus/pysecscan",
                        "rules": [{"id": r} for r in rules_seen],
                    }
                },
                "results": [_result(h) for h in findings],
            }
        ],
    }


def _emit(findings, root, fmt):
    if fmt == "json":
        payload = [
            {
                "path": str(h.path),
                "line": h.line,
                "rule": h.rule,
                "match": h.match,
                "blob": h.blob,
            }
            for h in findings
        ]
        print(json.dumps(payload, indent=2))
    elif fmt == "sarif":
        print(json.dumps(_to_sarif(findings, root), indent=2))
    else:
        for h in findings:
            # prefix history findings with their short blob SHA so users can
            # see at a glance which finding is "live in tree" vs "in history".
            prefix = f"{h.blob}:" if h.blob else ""
            print(f"{prefix}{h.path}:{h.line}: [{h.rule}] {h.match}")
        print(f"\n{len(findings)} finding(s)")


def main():
    parser = argparse.ArgumentParser(prog="pysecscan", description="Scan for committed secrets.")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a path for secrets.")
    scan.add_argument("path")
    # text for humans tailing stdout, json for CI / piping into jq,
    # sarif for github code-scanning uploads.
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    # entropy is noisier than named rules. let users tune it up to cut FPs,
    # or turn it off entirely when they only trust the curated patterns.
    scan.add_argument("--entropy-threshold", type=float, default=DEFAULT_ENTROPY)
    scan.add_argument("--no-entropy", action="store_true")
    # gitignore is respected by default. real-world repos rely on it to keep
    # generated junk out, and scanning that junk is just noise.
    scan.add_argument("--no-gitignore", action="store_true")
    # extra patterns to skip (same syntax as .gitignore). repeatable.
    scan.add_argument("--exclude", action="append", default=[], metavar="PATTERN")

    hist = sub.add_parser("history", help="Scan a git repo's full history for secrets.")
    hist.add_argument("repo", nargs="?", default=".")
    hist.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    hist.add_argument("--entropy-threshold", type=float, default=DEFAULT_ENTROPY)
    hist.add_argument("--no-entropy", action="store_true")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if args.command == "scan":
        root = Path(args.path)
        if not root.exists():
            # exit 2 for "wrong usage / bad input". keeps it distinct from
            # exit 1, which we reserve for "scan ran and found something".
            print(f"error: path does not exist: {root}", file=sys.stderr)
            sys.exit(2)

        threshold = None if args.no_entropy else args.entropy_threshold

        findings = []
        for f in walk(
            root,
            respect_gitignore=not args.no_gitignore,
            extra_excludes=args.exclude,
        ):
            for hit in scan_file(f, entropy_threshold=threshold):
                findings.append(hit)

        _emit(findings, root, args.format)
        # non-zero on findings so pre-commit hooks and CI fail the build
        # automatically. that's the whole point of running this in a pipeline.
        sys.exit(1 if findings else 0)

    if args.command == "history":
        repo = Path(args.repo)
        if not is_git_repo(repo):
            print(f"error: not a git repo: {repo}", file=sys.stderr)
            sys.exit(2)

        threshold = None if args.no_entropy else args.entropy_threshold

        findings = []
        for sha, path in iter_blobs(repo):
            # decode lossily: a historical blob isn't guaranteed to be utf-8.
            # we're scanning for ascii-ish secret patterns either way.
            content = read_blob(repo, sha).decode("utf-8", errors="replace")
            for hit in scan_text(Path(path), content, entropy_threshold=threshold):
                # carry the short blob SHA on the finding so reports show
                # which version of the file the secret lived in.
                findings.append(
                    Finding(hit.path, hit.line, hit.rule, hit.match, blob=sha[:12])
                )

        _emit(findings, repo, args.format)
        sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
