#!/usr/bin/env bash
# Builds a version of magicpipes for benchmarking, into target/bench/<name>, and the load tools from
# the working tree into target/bench/tools. With --target, into target/bench/<target>/.
#
# Usage: build.sh <name> [git revision] [--target <rust target>]
#
#   build.sh new                   the working tree, uncommitted changes included
#   build.sh base origin/main      a commit, which the working tree doesn't have to be on
#   build.sh new --target aarch64-unknown-linux-musl     for another machine; see README.md
set -euo pipefail

USAGE="usage: build.sh <name> [git revision] [--target <rust target>]"
NAME=${1:?$USAGE}
shift
REV="" TARGET="" TARGET_FLAG="" PROFILE_DIR=release
while [ $# -gt 0 ]; do
  case $1 in
    --target)
      TARGET=${2:?$USAGE}
      TARGET_FLAG="--target $TARGET"
      PROFILE_DIR=$TARGET/release
      shift 2
      ;;
    *)
      REV=$1
      shift
      ;;
  esac
done

REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=$REPO/target/bench${TARGET:+/$TARGET}
SOURCE=$REPO BUILT=$REPO/target
if [ -n "$REV" ]; then
  SOURCE=$(mktemp -d /tmp/mpbench-source.XXXXXX)
  trap 'rm -rf "$SOURCE"' EXIT
  git -C "$REPO" archive "$REV" | tar -x -C "$SOURCE"
  # Never the working tree's target folder, and always fresh timestamps. Cargo names a workspace's
  # crates by their path inside it and goes by file times, so it would take another version's output
  # for up to date, and link the wrong code without a word.
  BUILT=$REPO/target/bench/cargo-revisions
  find "$SOURCE" -type f -exec touch {} +
fi

mkdir -p "$OUT/$NAME" "$OUT/tools"
# shellcheck disable=SC2086
(cd "$SOURCE" && CARGO_TARGET_DIR=$BUILT cargo build --release --locked --bin magicpipes --bin magicpipesd $TARGET_FLAG)
cp "$BUILT/$PROFILE_DIR/magicpipes" "$BUILT/$PROFILE_DIR/magicpipesd" "$OUT/$NAME/"
# shellcheck disable=SC2086
(cd "$REPO" && cargo build --release --locked -p magicpipes-bench $TARGET_FLAG)
cp "$REPO/target/$PROFILE_DIR/mp-bench-load" "$REPO/target/$PROFILE_DIR/mp-bench-app" "$OUT/tools/"
echo "built $OUT/$NAME"
