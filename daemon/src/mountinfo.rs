//! Minimal /proc/self/mountinfo parser — just enough to locate a mount
//! entry by mountpoint and check its filesystem type.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// The kernel's id for this mount. Unique among *live* mounts only: the
    /// number is handed back when the mount goes away and given out again
    /// later, so on its own it does not say that a mount seen now is the one
    /// seen before. Use [`MountEntry::key`] to compare across time.
    pub id: String,
    pub mount_point: PathBuf,
    pub fstype: String,
    pub source: String,
    /// The mounted filesystem's device, as `major:minor`. For FUSE the minor
    /// is the connection number under /sys/fs/fuse/connections, which is how
    /// a mount can be tied to the descriptor that serves it. Also reused.
    pub dev: String,
}

impl MountEntry {
    /// How this mount is recognised again in a later reading. The id alone
    /// is not enough — it is recycled — so it is paired with where the mount
    /// sits. A recycled id somewhere new is then correctly a different
    /// mount, which is the case that matters when deciding whether a mount
    /// appeared during an operation.
    pub fn key(&self) -> String {
        format!("{}@{}", self.id, self.mount_point.display())
    }
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
            id: fields[0].to_string(),
            mount_point: PathBuf::from(unescape(fields[4])),
            fstype: fields[sep + 1].to_string(),
            source: unescape(fields[sep + 2]),
            dev: fields[2].to_string(),
        });
    }
    entries
}

/// Read the mount table.
///
/// The kernel builds this file as it is read, a page of records at a time,
/// so it takes several reads and mounts coming and going elsewhere in the
/// session can leave a reading without an entry that was there throughout.
/// Callers must therefore treat a single "not there" as a maybe: see how
/// `sweep_stale` asks twice before forgetting a mount it is responsible for.
fn read_table() -> std::io::Result<String> {
    std::fs::read_to_string("/proc/self/mountinfo")
}

/// Every FUSE mount in the live mount table.
pub fn fuse_mounts() -> std::io::Result<Vec<MountEntry>> {
    let content = read_table()?;
    Ok(parse(&content)
        .into_iter()
        .filter(|e| e.fstype.starts_with("fuse"))
        .collect())
}

/// Whether the kernel is actually publishing its FUSE connection list.
///
/// `/sys/fs/fuse/connections` exists as an ordinary empty directory whenever
/// `fusectl` is not mounted — the usual state inside a container, and not
/// guaranteed anywhere. Reading it then succeeds and yields nothing, which
/// is indistinguishable from "there are no connections" unless you look for
/// the filesystem itself. Getting that wrong is not harmless: it silently
/// turns "I cannot tell which connection I caused" into "I caused none",
/// which switches off the cleanup of a mount that landed astray.
pub fn fusectl_mounted() -> bool {
    read_table()
        .map(|content| parse(&content).iter().any(|e| e.fstype == "fusectl"))
        .unwrap_or(false)
}

/// The FUSE connections the kernel currently has open, by number.
///
/// A connection appears here the moment `fusermount3` opens `/dev/fuse` and
/// mounts, so comparing this before and after an operation names exactly the
/// connection the daemon caused — and `dev` on a mount entry ties that
/// connection to the mountpoint it ended up on, wherever that turned out
/// to be. `None` when the list is not being published at all.
pub fn fuse_connections() -> std::io::Result<Option<std::collections::HashSet<String>>> {
    if !fusectl_mounted() {
        return Ok(None);
    }
    let mut ids = std::collections::HashSet::new();
    for entry in std::fs::read_dir("/sys/fs/fuse/connections")? {
        if let Some(name) = entry?.file_name().to_str() {
            ids.insert(format!("0:{name}"));
        }
    }
    Ok(Some(ids))
}

/// The kernel's non-recycled identifier for the mount that `path` is on.
///
/// Everything the mount table offers is reused. Measured on Linux 6.18:
/// unmount a FUSE filesystem and mount another at the same path, and both
/// the mount id and the connection number come back identical on the very
/// next attempt — three times out of three. So the table cannot answer
/// "is the mount standing here the one I saw here before", which is the
/// question that decides whether a record still describes anything.
///
/// `STATX_MNT_ID_UNIQUE` (Linux 6.8) is documented not to be reused, and was
/// observed to differ on each of those same three mounts. It also answers
/// for a mount whose server has died: `ls` on such a mountpoint fails with
/// ENOTCONN while this still reports the id, which matters because removing
/// dead mounts is most of what unmounting is for.
///
/// `None` when the kernel does not supply it — before 6.8, notably on the
/// 6.1 kernel of Debian 12 — leaving the caller to fall back on the table.
pub fn unique_mount_id(path: &Path) -> Option<u64> {
    // Not in the libc crate yet.
    const STATX_MNT_ID_UNIQUE: libc::c_uint = 0x4000;
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: the path is a valid NUL-terminated string that outlives the
    // call, and the buffer is owned by this frame.
    let rc = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c_path.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
            STATX_MNT_ID_UNIQUE,
            &mut stx,
        )
    };
    // The mask is the kernel saying which fields it actually filled: asking
    // for a field it does not know about is not an error, it is a silence.
    if rc != 0 || stx.stx_mask & STATX_MNT_ID_UNIQUE == 0 {
        return None;
    }
    Some(stx.stx_mnt_id)
}

/// Could this mount be one this operation caused? It has to sit somewhere
/// other than the approved directory, and it has to be new.
///
/// `connections` narrows that further to mounts whose FUSE connection also
/// appeared during the operation. It is `None` when the kernel is not
/// publishing connections, and then the narrowing is simply skipped: what
/// decides in the end is the liveness transition, which is the argument
/// that carries the weight anyway. Skipping a narrowing widens the field of
/// candidates; it does not remove anything on its own.
pub fn could_be_from_this_operation(
    entry: &MountEntry,
    approved: &Path,
    before: &std::collections::HashSet<String>,
    connections: Option<&std::collections::HashSet<String>>,
) -> bool {
    entry.mount_point != approved
        && !before.contains(&entry.key())
        && connections.is_none_or(|c| c.contains(&entry.dev))
}

/// Read the live mountinfo and find the entry for `mount_point`, if any.
/// If several entries stack on the same path, the last (topmost) wins.
pub fn find(mount_point: &Path) -> std::io::Result<Option<MountEntry>> {
    let content = read_table()?;
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

    fn entry(id: &str, dev: &str, at: &str) -> MountEntry {
        MountEntry {
            id: id.into(),
            dev: dev.into(),
            mount_point: PathBuf::from(at),
            fstype: "fuse.test".into(),
            source: "test".into(),
        }
    }

    /// Without a connection list the narrowing has to be skipped, not
    /// treated as "no connections are new". Reading it as the latter is what
    /// silently switched off the removal of a misplaced mount on any system
    /// where fusectl is not mounted — found by running the suite in a
    /// container, where the directory exists but stays empty.
    #[test]
    fn an_unavailable_connection_list_widens_rather_than_empties_the_field() {
        let stray = entry("99", "0:157", "/victim/.ssh");
        let approved = Path::new("/root/a/.ssh");
        let before = std::collections::HashSet::new();

        // Unavailable: still a candidate, to be decided by liveness.
        assert!(could_be_from_this_operation(
            &stray, approved, &before, None
        ));
        // Available and matching: a candidate, as before.
        let ours: std::collections::HashSet<String> = ["0:157".to_string()].into_iter().collect();
        assert!(could_be_from_this_operation(
            &stray,
            approved,
            &before,
            Some(&ours)
        ));
        // Available and not matching: somebody else's connection.
        let other: std::collections::HashSet<String> = ["0:2".to_string()].into_iter().collect();
        assert!(!could_be_from_this_operation(
            &stray,
            approved,
            &before,
            Some(&other)
        ));
    }

    #[test]
    fn the_approved_mount_and_pre_existing_mounts_are_never_candidates() {
        let approved = Path::new("/root/a/.ssh");
        let before: std::collections::HashSet<String> =
            [entry("7", "0:157", "/somewhere/else").key()]
                .into_iter()
                .collect();

        // The mount that landed where it was supposed to.
        assert!(!could_be_from_this_operation(
            &entry("99", "0:157", "/root/a/.ssh"),
            approved,
            &before,
            None
        ));
        // A mount that was already there when the operation started.
        assert!(!could_be_from_this_operation(
            &entry("7", "0:157", "/somewhere/else"),
            approved,
            &before,
            None
        ));
    }

    /// Mount ids are handed back and given out again. A stray mount that
    /// picks up the number of one that has since gone must still count as
    /// new, or it is never cleaned up — which is why the comparison is by
    /// id *and* place rather than by id.
    #[test]
    fn a_recycled_mount_id_somewhere_new_is_still_a_new_mount() {
        let approved = Path::new("/root/a/.ssh");
        let before: std::collections::HashSet<String> = [entry("7", "0:157", "/gone/by/now").key()]
            .into_iter()
            .collect();

        assert!(could_be_from_this_operation(
            &entry("7", "0:157", "/victim/.ssh"),
            approved,
            &before,
            None
        ));
    }
}
