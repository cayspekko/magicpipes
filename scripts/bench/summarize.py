#!/usr/bin/env python3
"""Averages the runs of `bench.sh` that `compare.sh` saved, and compares the builds.

  summarize.py <results folder> <build> [<build>...]

Reads <build>.<round>.txt. The change column compares each build with the first one, and says so
when the two builds' runs overlap, because then the difference may be nothing but noise.
"""

import pathlib
import re
import sys

LOWER_IS_BETTER = {"p50", "p99", "mb", "ms", "us_per_req"}
UNITS = {"rps": "req/s", "mb_s": "MB/s", "gbit": "Gbit/s", "p50": "ms median", "p99": "ms p99", "mb": "MB", "ms": "ms", "us_per_req": "CPU µs/req"}


def read(path):
    for line in path.read_text().splitlines():
        fields = dict(part.split("=", 1) for part in line.split() if "=" in part)
        if "test" in fields and fields.get("key") in fields:
            yield fields


def number(value):
    if value >= 1000:
        return f"{value:,.0f}"
    return f"{value:.1f}" if value >= 10 else f"{value:.2f}"


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    folder, builds = pathlib.Path(sys.argv[1]), sys.argv[2:]
    values, keys, tests, problems = {}, {}, [], []
    for build in builds:
        for path in sorted(folder.glob(f"{build}.*.txt")):
            for fields in read(path):
                test, key = fields["test"], fields["key"]
                if test not in keys:
                    tests.append(test)
                keys[test] = key
                values.setdefault((build, test), []).append(float(fields[key]))
                bad = [s for s in fields.get("status", "-").split(",") if s != "-" and not re.match(r"[23]\d\d:", s)]
                failed = int(fields.get("failed", 0)) + int(fields.get("connect_failed", 0))
                if bad or failed:
                    errors = fields.get("errors", "-")
                    problems.append(f"{path.stem} {test}: {failed} failed, statuses {','.join(bad) or '-'}, errors {errors}")

    rows = [["test"] + builds + (["change"] if len(builds) > 1 else [])]
    for test in tests:
        key = keys[test]
        row = [f"{test} ({UNITS.get(key, key)})"]
        for build in builds:
            runs = values.get((build, test))
            if not runs:
                row.append("-")
                continue
            average = sum(runs) / len(runs)
            spread = (max(runs) - min(runs)) / 2 / average * 100 if average else 0
            row.append(number(average) + (f" ±{spread:.0f}%" if len(runs) > 1 else ""))
        if len(builds) > 1:
            row.append(change(values.get((builds[0], test)), values.get((builds[-1], test)), key))
        rows.append(row)

    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    for row in rows:
        print("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())
    if problems:
        print("\nRequests that failed or were refused:")
        for problem in problems:
            print(f"  {problem}")


def change(before, after, key):
    if not before or not after:
        return "-"
    old, new = sum(before) / len(before), sum(after) / len(after)
    if not old:
        return "-"
    better = new < old if key in LOWER_IS_BETTER else new > old
    text = f"{(new - old) / old * 100:+.0f}% {'better' if better else 'worse'}"
    if len(before) > 1 and len(after) > 1 and min(after) <= max(before) and min(before) <= max(after):
        return text + " (runs overlap)"
    return text


if __name__ == "__main__":
    main()
