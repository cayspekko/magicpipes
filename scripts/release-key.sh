#!/bin/sh
# Makes the Ed25519 key releases are signed with. Run once, by the project's owner, with an
# OpenSSL that has Ed25519 (OpenSSL 3 or later):
#
#   scripts/release-key.sh [file]          # default: magicpipes-release-key.pem
#
# It prints the public half, to add to RELEASE_KEYS in crates/magicpipes-core/src/release.rs (a
# binary only installs releases signed by a key it was built with), and how to store the private
# half as the secret the release workflow signs with. Nothing is sent anywhere.
set -eu

# The default name is in .gitignore, so it's never committed from the repository.
out=${1:-magicpipes-release-key.pem}
if [ -e "$out" ]; then
  echo "$out already exists; not replacing it" >&2
  exit 1
fi
umask 077
openssl genpkey -algorithm ed25519 -out "$out"
pub=$(openssl pkey -in "$out" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')

cat <<EOF
Made $out (readable by you only).

1. Add the public key to RELEASE_KEYS in crates/magicpipes-core/src/release.rs, and commit it:

       pub const RELEASE_KEYS: &[&str] = &["$pub"];

2. Store the private key as the secret the release workflow signs with, in an environment named
   "release" (GitHub: Settings > Environments > New environment), for example with the GitHub CLI:

       gh secret set MAGICPIPES_RELEASE_KEY --env release < $out

3. Then delete $out, or keep it offline: anyone who has it can sign a release every binary with
   this public key will install.
EOF
