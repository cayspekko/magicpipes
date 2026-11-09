//! noVNC's library, vendored unchanged in `assets/vnc/novnc/` (its README has the version and
//! digest): every file the VNC page can import, by its path under that folder.

pub(super) const FILES: &[(&str, &str)] = &[
    ("core/base64.js", include_str!("assets/vnc/novnc/core/base64.js")),
    ("core/crypto/aes.js", include_str!("assets/vnc/novnc/core/crypto/aes.js")),
    ("core/crypto/bigint.js", include_str!("assets/vnc/novnc/core/crypto/bigint.js")),
    ("core/crypto/crypto.js", include_str!("assets/vnc/novnc/core/crypto/crypto.js")),
    ("core/crypto/des.js", include_str!("assets/vnc/novnc/core/crypto/des.js")),
    ("core/crypto/dh.js", include_str!("assets/vnc/novnc/core/crypto/dh.js")),
    ("core/crypto/md5.js", include_str!("assets/vnc/novnc/core/crypto/md5.js")),
    ("core/crypto/rsa.js", include_str!("assets/vnc/novnc/core/crypto/rsa.js")),
    ("core/decoders/copyrect.js", include_str!("assets/vnc/novnc/core/decoders/copyrect.js")),
    ("core/decoders/h264.js", include_str!("assets/vnc/novnc/core/decoders/h264.js")),
    ("core/decoders/hextile.js", include_str!("assets/vnc/novnc/core/decoders/hextile.js")),
    ("core/decoders/jpeg.js", include_str!("assets/vnc/novnc/core/decoders/jpeg.js")),
    ("core/decoders/raw.js", include_str!("assets/vnc/novnc/core/decoders/raw.js")),
    ("core/decoders/rre.js", include_str!("assets/vnc/novnc/core/decoders/rre.js")),
    ("core/decoders/tight.js", include_str!("assets/vnc/novnc/core/decoders/tight.js")),
    ("core/decoders/tightpng.js", include_str!("assets/vnc/novnc/core/decoders/tightpng.js")),
    ("core/decoders/zlib.js", include_str!("assets/vnc/novnc/core/decoders/zlib.js")),
    ("core/decoders/zrle.js", include_str!("assets/vnc/novnc/core/decoders/zrle.js")),
    ("core/deflator.js", include_str!("assets/vnc/novnc/core/deflator.js")),
    ("core/display.js", include_str!("assets/vnc/novnc/core/display.js")),
    ("core/encodings.js", include_str!("assets/vnc/novnc/core/encodings.js")),
    ("core/inflator.js", include_str!("assets/vnc/novnc/core/inflator.js")),
    ("core/input/domkeytable.js", include_str!("assets/vnc/novnc/core/input/domkeytable.js")),
    ("core/input/fixedkeys.js", include_str!("assets/vnc/novnc/core/input/fixedkeys.js")),
    ("core/input/gesturehandler.js", include_str!("assets/vnc/novnc/core/input/gesturehandler.js")),
    ("core/input/keyboard.js", include_str!("assets/vnc/novnc/core/input/keyboard.js")),
    ("core/input/keysym.js", include_str!("assets/vnc/novnc/core/input/keysym.js")),
    ("core/input/keysymdef.js", include_str!("assets/vnc/novnc/core/input/keysymdef.js")),
    ("core/input/util.js", include_str!("assets/vnc/novnc/core/input/util.js")),
    ("core/input/vkeys.js", include_str!("assets/vnc/novnc/core/input/vkeys.js")),
    ("core/input/xtscancodes.js", include_str!("assets/vnc/novnc/core/input/xtscancodes.js")),
    ("core/ra2.js", include_str!("assets/vnc/novnc/core/ra2.js")),
    ("core/rfb.js", include_str!("assets/vnc/novnc/core/rfb.js")),
    ("core/util/browser.js", include_str!("assets/vnc/novnc/core/util/browser.js")),
    ("core/util/cursor.js", include_str!("assets/vnc/novnc/core/util/cursor.js")),
    ("core/util/element.js", include_str!("assets/vnc/novnc/core/util/element.js")),
    ("core/util/events.js", include_str!("assets/vnc/novnc/core/util/events.js")),
    ("core/util/eventtarget.js", include_str!("assets/vnc/novnc/core/util/eventtarget.js")),
    ("core/util/int.js", include_str!("assets/vnc/novnc/core/util/int.js")),
    ("core/util/logging.js", include_str!("assets/vnc/novnc/core/util/logging.js")),
    ("core/util/strings.js", include_str!("assets/vnc/novnc/core/util/strings.js")),
    ("core/websock.js", include_str!("assets/vnc/novnc/core/websock.js")),
    ("vendor/pako/lib/utils/common.js", include_str!("assets/vnc/novnc/vendor/pako/lib/utils/common.js")),
    ("vendor/pako/lib/zlib/adler32.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/adler32.js")),
    ("vendor/pako/lib/zlib/constants.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/constants.js")),
    ("vendor/pako/lib/zlib/crc32.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/crc32.js")),
    ("vendor/pako/lib/zlib/deflate.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/deflate.js")),
    ("vendor/pako/lib/zlib/gzheader.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/gzheader.js")),
    ("vendor/pako/lib/zlib/inffast.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/inffast.js")),
    ("vendor/pako/lib/zlib/inflate.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/inflate.js")),
    ("vendor/pako/lib/zlib/inftrees.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/inftrees.js")),
    ("vendor/pako/lib/zlib/messages.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/messages.js")),
    ("vendor/pako/lib/zlib/trees.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/trees.js")),
    ("vendor/pako/lib/zlib/zstream.js", include_str!("assets/vnc/novnc/vendor/pako/lib/zlib/zstream.js")),
];

#[cfg(test)]
mod tests {
    /// A file added to the folder (a new noVNC version) and not listed here would be a 404 to the
    /// page, so the list must be the folder's scripts, exactly.
    #[test]
    fn every_script_in_the_folder_is_served() {
        fn walk(dir: &std::path::Path, base: &std::path::Path, found: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, base, found);
                } else if path.extension().is_some_and(|e| e == "js") {
                    found.push(path.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
                }
            }
        }
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/mgmt/assets/vnc/novnc");
        let mut found = Vec::new();
        walk(&base, &base, &mut found);
        found.sort();
        let mut listed: Vec<String> = super::FILES.iter().map(|(p, _)| p.to_string()).collect();
        listed.sort();
        assert_eq!(found, listed);
    }
}
