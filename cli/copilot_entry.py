#!/usr/bin/env python3
"""
Copilot CLI entry point for MuleSoft code review.

Usage examples:
    python cli/copilot_entry.py review --path ./repo
    python cli/copilot_entry.py list-flows --path ./repo
    python cli/copilot_entry.py orphan-check --path ./repo
"""

import argparse
import sys
from mule_validator.main import run

def run_full_review(path):
    print(f"\n🔍 Running full MuleSoft code review on: {path}\n")
    run(path, mode="full")

def run_list_flows(path):
    print(f"\n📄 Listing flows and subflows in: {path}\n")
    run(path, mode="list-flows")

def run_orphan_check(path):
    print(f"\n🚨 Checking for orphan flows in: {path}\n")
    run(path, mode="orphan-check")
    
def main():
    parser = argparse.ArgumentParser(
        description="Copilot CLI entry for MuleSoft code review"
    )
    parser.add_argument(
        "--path", "-p", required=True, help="Path to the MuleSoft project"
    )

    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("review", help="Run full code review")
    subparsers.add_parser("list-flows", help="List flows and subflows")
    subparsers.add_parser("orphan-check", help="Detect orphan flows")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "review":
        run_full_review(args.path)
    elif args.command == "list-flows":
        run_list_flows(args.path)
    elif args.command == "orphan-check":
        run_orphan_check(args.path)
    else:
        print(f"Unknown command: {args.command}")
        parser.print_help()

if __name__ == "__main__":
    main()
