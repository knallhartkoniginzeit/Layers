from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from layers import diagnose
from layers.ingest.har import from_har
from layers.report.json_out import render_json
from layers.report.terminal import render_terminal


def main() -> None:
    parser = argparse.ArgumentParser(description="Diagnose a failed API call from a HAR file.")
    parser.add_argument("har_file", type=Path, help="Path to the .har file")
    parser.add_argument(
        "--entry",
        type=int,
        default=0,
        help="Index of the HAR entry to diagnose (default: 0 = first failed)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Output diagnosis as JSON instead of terminal",
    )
    args = parser.parse_args()

    if not args.har_file.exists():
        print(f"Error: file not found: {args.har_file}", file=sys.stderr)
        sys.exit(1)

    har_text = args.har_file.read_text(encoding="utf-8")

    try:
        har_data = json.loads(har_text)
        entries = har_data.get("log", {}).get("entries", [])
    except json.JSONDecodeError as e:
        print(f"Error: invalid HAR JSON: {e}", file=sys.stderr)
        sys.exit(1)

    if not entries:
        print("Error: HAR file contains no entries.", file=sys.stderr)
        sys.exit(1)

    target_entry = None
    if args.entry == 0:
        for entry in entries:
            status = entry.get("response", {}).get("status", 0)
            if status == 0 or status >= 400:
                target_entry = entry
                break
        if target_entry is None:
            print("No failed entries found in HAR. Using first entry.")
            target_entry = entries[0]
    else:
        if args.entry >= len(entries):
            print(
                f"Error: entry index {args.entry} out of range (HAR has {len(entries)} entries)",
                file=sys.stderr,
            )
            sys.exit(1)
        target_entry = entries[args.entry]

    case = from_har(json.dumps(target_entry))

    print(f"\nDiagnosing: {case.method} {case.url}")
    print(f"Status: {case.status or 'No response'}")
    print(f"Elapsed: {case.elapsed_ms or 0:.0f} ms\n")

    diagnosis = diagnose(case)

    if args.output_json:
        print(render_json(diagnosis))
    else:
        render_terminal(diagnosis)


if __name__ == "__main__":
    main()
