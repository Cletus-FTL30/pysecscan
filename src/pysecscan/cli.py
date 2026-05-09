import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pysecscan",
        description="Scan a repository for accidentally committed secrets.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan a path for secrets.")
    scan_parser.add_argument("path", help="Path to the directory or file to scan.")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        print(f"Scanning: {args.path}")
        print("(detection logic coming soon)")


if __name__ == "__main__":
    main()
