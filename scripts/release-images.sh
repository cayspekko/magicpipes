#!/usr/bin/env bash
# Builds a release's container images, the server (magicpipes) and the agent (magicpipes-agent), for
# linux/amd64 and linux/arm64, from the static binaries the release has already built and smoke-tested
# (docker/Dockerfile.release). Needs docker with buildx and a builder that can build for several
# platforms (docker/setup-buildx-action's default).
#
#   scripts/release-images.sh <dir> <tag>
#       builds both images for both platforms and runs the binary of each image this machine can run
#   scripts/release-images.sh <dir> <tag> --push <repository>
#       builds and pushes <repository>/magicpipes and <repository>/magicpipes-agent, tagged with the
#       version and, unless it's a pre-release such as 0.3.0-rc.1, `latest`; docker must already be
#       signed in to the registry
#
# <dir> holds the release's bare binaries, named <binary>-<tag>-<target> as release.yml uploads them.
set -euo pipefail

usage() { echo "usage: release-images.sh <dir> <tag> [--push <repository>]" >&2; exit 2; }
[[ $# -eq 2 || ( $# -eq 4 && $3 == --push ) ]] || usage
DIR=$1 TAG=$2 REPOSITORY=${4:-}
VERSION=${TAG#v}
DOCKERFILE=$(cd "$(dirname "$0")/.." && pwd)/docker/Dockerfile.release

CONTEXT=$(mktemp -d)
trap 'rm -r -- "$CONTEXT"' EXIT
for platform in amd64:x86_64 arm64:aarch64; do
  arch=${platform%%:*} target=${platform#*:}-unknown-linux-musl
  mkdir "$CONTEXT/$arch"
  for binary in magicpipes magicpipesd; do
    cp "$DIR/$binary-$TAG-$target" "$CONTEXT/$arch/$binary"
  done
done

LABELS=(--label "org.opencontainers.image.source=https://github.com/cayspekko/magicpipes"
        --label "org.opencontainers.image.version=$VERSION")
HOST_ARCH=$(docker version --format '{{.Server.Arch}}')

for image in magicpipes magicpipes-agent; do
  target=()
  [[ $image == magicpipes-agent ]] && target=(--target agent)
  if [[ -n "$REPOSITORY" ]]; then
    tags=(-t "$REPOSITORY/$image:$VERSION")
    [[ $VERSION == *-* ]] || tags+=(-t "$REPOSITORY/$image:latest")
    echo "== pushing $REPOSITORY/$image:$VERSION"
    docker buildx build -f "$DOCKERFILE" "${target[@]}" --platform linux/amd64,linux/arm64 "${LABELS[@]}" \
      "${tags[@]}" --push "$CONTEXT"
  else
    for arch in amd64 arm64; do
      echo "== building $image for linux/$arch"
      docker buildx build -f "$DOCKERFILE" "${target[@]}" --platform "linux/$arch" "${LABELS[@]}" \
        -t "$image-check:$arch" --load "$CONTEXT"
      [[ $arch == "$HOST_ARCH" ]] || continue
      binary=magicpipesd
      [[ $image == magicpipes-agent ]] && binary=magicpipes
      docker run --rm --entrypoint "/usr/local/bin/$binary" "$image-check:$arch" --version
    done
  fi
done
