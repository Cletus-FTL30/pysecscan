import argparse
import json
import sys
from pathlib import Path

from pysecscan.detectors import DEFAULT_ENTROPY, scan_file
from pysecscan.walker import walk


def main():
    parser = argparse.ArgumentParser(prog="pysecscan", description="Scan for committed secrets.")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a path for secrets.")
    scan.add_argument("path")
    # text for humans tailing stdout, json for CI / piping into jq.
    scan.add_argument("--format", choices=["text", "json"], default="text")
    # entropy is noisier than named rules. let users tune it up to cut FPs,
    # or turn it off entirely when they only trust the curated patterns.
    scan.add_argument("--entropy-threshold", type=float, default=DEFAULT_ENTROPY)
    scan.add_argument("--no-entropy", action="store_true")
    # gitignore is respected by default. real-world repos rely on it to keep
    # generated junk out, and scanning that junk is just noise.
    scan.add_argument("--no-gitignore", action="store_true")
    # extra patterns to skip (same syntax as .gitignore). repeatable.
    scan.add_argument("--exclude", action="append", default=[], metavar="PATTERN")

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

        if args.format == "json":
            # buffer everything and dump once so the output is a single valid
            # JSON document, not a stream of objects. easier to consume.
            payload = [
                {"path": str(h.path), "line": h.line, "rule": h.rule, "match": h.match}
                for h in findings
            ]
            print(json.dumps(payload, indent=2))
        else:
            for h in findings:
                print(f"{h.path}:{h.line}: [{h.rule}] {h.match}")
            print(f"\n{len(findings)} finding(s) in {root}")

        # non-zero on findings so pre-commit hooks and CI fail the build
        # automatically. that's the whole point of running this in a pipeline.
        sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
