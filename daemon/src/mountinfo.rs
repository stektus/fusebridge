//! Minimal /proc/self/mountinfo parser — just enough to locate a mount
//! entry by mountpoint and check its filesystem type.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub mount_point: PathBuf,
    pub fstype: String,
    pub source: String,
}

/// Unescape the octal sequences mountinfo uses for special characters
/// (\040 space, \011 tab, \012 newline, \134 backslash).
fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &s[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(oct, 8) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse mountinfo content. Lines that do not conform are skipped.
pub fn parse(content: &str) -> Vec<MountEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        // Format: id parent maj:min root mountpoint mntopts [optional...] - fstype source superopts
        if fields.len() < 10 {
            continue;
        }
        let Some(sep) = fields.iter().position(|f| *f == "-") else {
            continue;
        };
        if sep < 6 || sep + 2 >= fields.len() {
            continue;
        }
        entries.push(MountEntry {
            mount_point: PathBuf::from(unescape(fields[4])),
            fstype: fields[sep + 1].to_string(),
            source: unescape(fields[sep + 2]),
        });
    }
    entries
}

/// Read the live mountinfo and find the entry for `mount_point`, if any.
/// If several entries stack on the same path, the last (topmost) wins.
pub fn find(mount_point: &Path) -> std::io::Result<Option<MountEntry>> {
    let content = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(parse(&content)
        .into_iter()
        .rfind(|e| e.mount_point == mount_point))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_regular_line() {
        let line = "36 35 98:0 / /mnt/data rw,noatime master:1 - ext4 /dev/sda1 rw";
        let e = &parse(line)[0];
        assert_eq!(e.mount_point, PathBuf::from("/mnt/data"));
        assert_eq!(e.fstype, "ext4");
        assert_eq!(e.source, "/dev/sda1");
    }

    #[test]
    fn parses_fuse_line_with_escaped_space() {
        let line = "1210 32 0:70 / /home/u/Cloud\\040Drives/d rw,nosuid,nodev - fuse.rclone :local: rw,user_id=1000";
        let e = &parse(line)[0];
        assert_eq!(e.mount_point, PathBuf::from("/home/u/Cloud Drives/d"));
        assert_eq!(e.fstype, "fuse.rclone");
        assert_eq!(e.source, ":local:");
    }

    #[test]
    fn skips_garbage_and_finds_topmost() {
        let content = "garbage line\n\
            36 35 98:0 / /m rw - ext4 /dev/sda1 rw\n\
            37 36 0:70 / /m rw - fuse.rclone :local: rw\n";
        let entries = parse(content);
        assert_eq!(entries.len(), 2);
        let top = entries
            .into_iter()
            .rfind(|e| e.mount_point == Path::new("/m"))
            .unwrap();
        assert_eq!(top.fstype, "fuse.rclone");
    }

    #[test]
    fn unescapes_backslash() {
        assert_eq!(unescape("a\\134b"), "a\\b");
        assert_eq!(unescape("no_escapes"), "no_escapes");
        assert_eq!(unescape("trail\\"), "trail\\");
    }
}
