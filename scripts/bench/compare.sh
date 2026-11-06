#!/usr/bin/env bash
# Runs a suite on several builds in turn, several rounds, and prints a table. Taking turns matters:
# a machine drifts, and a single run on a VM can be 10-20% off.
#
# Usage: compare.sh [--suite traffic|control|memory|wan] [--rounds N] <build> [<build>...]
#
# Builds are names in target/bench (or BENCH_DIR, on a machine without the repository's target
# folder). The first is what the others are compared with. Raw results stay in <that>/results.
set -uo pipefail

SUITE=traffic ROUNDS=3
while [ $# -gt 0 ]; do
  case $1 in
    --suite) SUITE=$2; shift 2 ;;
    --rounds) ROUNDS=$2; shift 2 ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { sed -n 5p "$0" | sed 's/^# //' >&2; exit 2; }

HERE=$(cd "$(dirname "$0")" && pwd)
DIR=$(cd "${BENCH_DIR:-$HERE/../../target/bench}" && pwd) || exit 2
RESULTS=$DIR/results/$SUITE-$(date +%Y%m%d-%H%M%S)
mkdir -p "$RESULTS"

for round in $(seq 1 "$ROUNDS"); do
  for build in "$@"; do
    echo "round $round of $ROUNDS: $build" >&2
    "$HERE/bench.sh" "$SUITE" "$DIR/$build" > "$RESULTS/$build.$round.txt" || {
      echo "the $SUITE suite failed on $build" >&2
      exit 1
    }
  done
done
echo "raw results: $RESULTS" >&2
python3 "$HERE/summarize.py" "$RESULTS" "$@"
