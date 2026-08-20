//! Mountpoint and mount-option policy.
//!
//! The daemon refuses anything it was not explicitly configured to allow:
//! a mountpoint must be an empty directory owned by the invoking user,
//! strictly inside one of the allowed roots. This is the defence against
//! mountpoint shadowing — mounting over `~/.ssh` so that the next ssh run
//! reads the attacker's keys.
//!
//! Checking a *path* would not be enough. `fusermount3` resolves the path
//! again when it runs, and it only rejects a symlink in the final
//! component: a caller that swaps a *parent* directory for a symlink
//! between the check and the mount redirects the mount anywhere it likes
//! (verified against fuse 3.18.2 — the mount landed outside the allowed
//! root). So the check resolves the path exactly once, keeps the resulting
//! directory open, and every later step works through that descriptor.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Checks still stuck in the kernel, and how many are tolerated.
///
/// Resolving a path can block forever — the path may lead through a FUSE
/// mount whose server has stopped answering, and an application can arrange
/// exactly that with a mount of its own. Each check therefore runs on its
/// own thread and is abandoned if it does not come back in time. Abandoned
/// threads are counted, and once too many are stuck the daemon stops
/// starting new ones rather than accumulating them without limit.
static STUCK_CHECKS: AtomicUsize = AtomicUsize::new(0);
const MAX_STUCK_CHECKS: usize = 32;

/// Mount options the daemon refuses to forward. `allow_other`/`allow_root`
/// would expose the sandboxed filesystem to other users of the machine.
const FORBIDDEN_OPTIONS: &[&str] = &["allow_other", "allow_root"];

pub fn check_options(options: &[String]) -> Result<(), String> {
    for opt in options {
        let key = opt.split('=').next().unwrap_or(opt);
        if FORBIDDEN_OPTIONS.contains(&key) {
            return Err(format!("mount option '{key}' is not allowed"));
        }
        if opt.contains(',') {
            return Err(format!("malformed mount option '{opt}'"));
        }
    }
    Ok(())
}

/// A mountpoint that passed policy, pinned by an open descriptor.
///
/// `dir` is the authority, not `path`: the mount is performed by making
/// this descriptor the working directory of `fusermount3` and passing "."
/// as the mountpoint, so no path is ever resolved a second time. `path` is
/// what that descriptor resolved to at check time, kept for the journal and
/// for post-mount verification.
pub struct Approved {
    pub dir: File,
    pub path: PathBuf,
}

/// The path a descriptor currently refers to, via procfs.
pub fn fd_path(dir: &File) -> Result<PathBuf, String> {
    let link = format!("/proc/self/fd/{}", dir.as_raw_fd());
    let path =
        std::fs::read_link(&link).map_err(|e| format!("cannot resolve the mountpoint: {e}"))?;
    // procfs marks a removed directory this way; such a path is meaningless.
    if path.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") {
        return Err("the mountpoint was removed while it was being checked".into());
    }
    Ok(path)
}

/// Validate a mountpoint request, giving up if the filesystem it sits on
/// does not answer. See `STUCK_CHECKS`: without a deadline here, one
/// application could stop the daemon serving anyone else, for good.
pub fn check_mountpoint_within(
    raw: &str,
    allowed_roots: &[PathBuf],
    timeout: Duration,
) -> Result<Approved, String> {
    if STUCK_CHECKS.load(Ordering::Relaxed) >= MAX_STUCK_CHECKS {
        return Err(
            "too many mountpoint checks are stuck on filesystems that are not responding".into(),
        );
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let raw_owned = raw.to_string();
    let roots = allowed_roots.to_vec();
    STUCK_CHECKS.fetch_add(1, Ordering::Relaxed);
    std::thread::spawn(move || {
        let result = check_mountpoint(&raw_owned, &roots);
        STUCK_CHECKS.fetch_sub(1, Ordering::Relaxed);
        // If nobody is listening any more the descriptor is dropped here,
        // which is what should happen to a mountpoint nobody waited for.
        let _ = sender.send(result);
    });
    receiver.recv_timeout(timeout).unwrap_or_else(|_| {
        Err(format!(
            "'{raw}' did not answer within {} seconds: the filesystem it sits on is not responding",
            timeout.as_secs()
        ))
    })
}

/// Validate a mountpoint request, returning it pinned by a descriptor.
pub fn check_mountpoint(raw: &str, allowed_roots: &[PathBuf]) -> Result<Approved, String> {
    // One resolution, done here. O_DIRECTORY rejects non-directories,
    // including a symlink to a regular file; a symlink to a directory
    // resolves, and the real path it landed on is checked below.
    let dir = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(raw)
        .map_err(|e| format!("mountpoint '{raw}' cannot be opened: {e}"))?;

    let path = fd_path(&dir)?;

    let meta = dir
        .metadata()
        .map_err(|e| format!("cannot stat '{}': {e}", path.display()))?;
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(format!(
            "'{}' is owned by uid {}, not by the session user",
            path.display(),
            meta.uid()
        ));
    }

    // Read the directory through the same descriptor, so emptiness is
    // established for the inode that will be mounted on, not for whatever
    // the path happens to name now.
    let mut entries = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|e| format!("cannot read '{}': {e}", path.display()))?;
    if entries.next().is_some() {
        return Err(format!("'{}' is not empty", path.display()));
    }

    if !inside_allowed(&path, allowed_roots) {
        return Err(format!(
            "'{}' is outside the allowed mount roots ({})",
            path.display(),
            allowed_roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(Approved { dir, path })
}

/// True if `path` sits strictly inside one of the allowed roots.
/// A root is not a valid mountpoint itself: mounting over `~/CloudDrives`
/// would hide every other drive under it.
pub fn inside_allowed(path: &Path, allowed_roots: &[PathBuf]) -> bool {
    allowed_roots
        .iter()
        .any(|root| path.starts_with(root) && path != root)
}

/// Whether `caller_app` may unmount a mount recorded for `record_app`.
/// Mounts belong to the application that created them; a second app on the
/// bus must not be able to pull a filesystem out from under the first.
pub fn may_unmount(record_app: &str, caller_app: &str) -> bool {
    record_app == caller_app
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test gets its own directory; tests run in parallel threads.
    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fb-policy-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rejects_allow_other() {
        assert!(check_options(&["rw".into(), "allow_other".into()]).is_err());
        assert!(check_options(&["allow_root".into()]).is_err());
        assert!(check_options(&["rw".into(), "fsname=x".into()]).is_ok());
    }

    #[test]
    fn rejects_option_smuggling() {
        assert!(check_options(&["rw,allow_other".into()]).is_err());
    }

    #[test]
    fn mountpoint_must_be_inside_root_not_the_root() {
        let tmp = tmpdir("inside");
        let root = tmp.join("root");
        let inside = root.join("drive");
        std::fs::create_dir_all(&inside).unwrap();
        let allowed = vec![std::fs::canonicalize(&root).unwrap()];

        assert!(check_mountpoint(inside.to_str().unwrap(), &allowed).is_ok());
        assert!(check_mountpoint(root.to_str().unwrap(), &allowed).is_err());
        assert!(check_mountpoint("/", &allowed).is_err());

        std::fs::write(inside.join("file"), "x").unwrap();
        assert!(check_mountpoint(inside.to_str().unwrap(), &allowed).is_err());

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn symlink_out_of_root_is_rejected() {
        let tmp = tmpdir("sym");
        let root = tmp.join("root");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let allowed = vec![std::fs::canonicalize(&root).unwrap()];

        // The descriptor resolves to `outside`, which is not in the root.
        assert!(check_mountpoint(link.to_str().unwrap(), &allowed).is_err());

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn parent_symlink_out_of_root_is_rejected() {
        let tmp = tmpdir("parent-sym");
        let root = tmp.join("root");
        let victim = tmp.join("victim");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(victim.join(".ssh")).unwrap();
        std::os::unix::fs::symlink(&victim, root.join("a")).unwrap();
        let allowed = vec![std::fs::canonicalize(&root).unwrap()];

        // root/a/.ssh resolves to victim/.ssh: refused despite the prefix.
        let req = root.join("a").join(".ssh");
        assert!(check_mountpoint(req.to_str().unwrap(), &allowed).is_err());

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn approved_descriptor_survives_a_rename() {
        let tmp = tmpdir("pin");
        let root = tmp.join("root");
        let drive = root.join("drive");
        std::fs::create_dir_all(&drive).unwrap();
        let allowed = vec![std::fs::canonicalize(&root).unwrap()];

        let approved = check_mountpoint(drive.to_str().unwrap(), &allowed).unwrap();
        std::fs::rename(&drive, root.join("moved")).unwrap();
        // The descriptor still names the same inode, now at its new path.
        assert_eq!(fd_path(&approved.dir).unwrap(), root.join("moved"));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn root_prefix_is_compared_by_component() {
        let root = PathBuf::from("/home/u/CloudDrives");
        let allowed = vec![root.clone()];
        assert!(inside_allowed(Path::new("/home/u/CloudDrives/x"), &allowed));
        assert!(!inside_allowed(
            Path::new("/home/u/CloudDrivesEvil/x"),
            &allowed
        ));
        assert!(!inside_allowed(&root, &allowed));
    }

    #[test]
    fn unmount_is_restricted_to_the_owning_app() {
        assert!(may_unmount("org.example.App", "org.example.App"));
        assert!(!may_unmount("org.example.App", "org.evil.Other"));
    }
}
