import argparse
import sys
from pathlib import Path

from pysecscan.detectors import scan_file
from pysecscan.walker import walk


def main():
    parser = argparse.ArgumentParser(prog="pysecscan", description="Scan for committed secrets.")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a path for secrets.")
    scan.add_argument("path")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if args.command == "scan":
        root = Path(args.path)
        if not root.exists():
            print(f"error: path does not exist: {root}", file=sys.stderr)
            sys.exit(2)

        count = 0
        for f in walk(root):
            for hit in scan_file(f):
                print(f"{hit.path}:{hit.line}: [{hit.rule}] {hit.match}")
                count += 1

        print(f"\n{count} finding(s) in {root}")
        sys.exit(1 if count else 0)


if __name__ == "__main__":
    main()
