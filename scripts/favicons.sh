#!/bin/sh
# Renders the management UI's bitmap icons from crates/magicpipes-server/src/mgmt/assets/favicon-tile.svg
# with headless Chrome: favicon.ico (a 32 px PNG in an ICO container) and apple-touch-icon.png
# (180 px, square: iOS rounds the corners itself). favicon.svg is drawn by hand and used as is.
#   scripts/favicons.sh [path to Chrome]
set -eu
chrome=${1:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
dir=$(cd "$(dirname "$0")/../crates/magicpipes-server/src/mgmt/assets" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
render() { # svg, size, out
    # Chrome lays out a wider viewport than a small window; the image sits at the top left.
    printf '<html style="margin:0"><body style="margin:0"><img src="file://%s" width="%s" height="%s" style="display:block">' "$1" "$2" "$2" > "$tmp/page.html"
    "$chrome" --headless=new --disable-gpu --hide-scrollbars --default-background-color=00000000 \
        --force-device-scale-factor=1 --window-size="$2,$2" --screenshot="$3" "file://$tmp/page.html" 2>/dev/null
}
render "$dir/favicon-tile.svg" 32 "$tmp/32.png"
sed 's/rx="14"/rx="0"/' "$dir/favicon-tile.svg" > "$tmp/square.svg"
render "$tmp/square.svg" 180 "$dir/apple-touch-icon.png"
python3 - "$tmp/32.png" "$dir/favicon.ico" <<'PY'
import struct, sys
png = open(sys.argv[1], "rb").read()
# ICONDIR, then one ICONDIRENTRY pointing at the PNG data right after it.
ico = struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", 32, 32, 0, 0, 1, 32, len(png), 22) + png
open(sys.argv[2], "wb").write(ico)
PY
ls -l "$dir"
