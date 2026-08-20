//! Mountpoint and mount-option policy.
//!
//! The daemon refuses anything it was not explicitly configured to allow:
//! a mountpoint must be an empty directory owned by the invoking user,
//! strictly inside one of the allowed roots. This is the defence against
//! mountpoint shadowing (mounting over ~/.ssh and the like).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

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

/// Validate a mountpoint request and return its canonical path.
pub fn check_mountpoint(raw: &str, allowed_roots: &[PathBuf]) -> Result<PathBuf, String> {
    let mp = std::fs::canonicalize(raw)
        .map_err(|e| format!("mountpoint '{raw}' cannot be resolved: {e}"))?;

    let meta = std::fs::symlink_metadata(&mp)
        .map_err(|e| format!("cannot stat '{}': {e}", mp.display()))?;
    if !meta.is_dir() {
        return Err(format!("'{}' is not a directory", mp.display()));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(format!(
            "'{}' is owned by uid {}, not by the session user",
            mp.display(),
            meta.uid()
        ));
    }
    let mut it =
        std::fs::read_dir(&mp).map_err(|e| format!("cannot read '{}': {e}", mp.display()))?;
    if it.next().is_some() {
        return Err(format!("'{}' is not empty", mp.display()));
    }

    let inside_allowed = allowed_roots
        .iter()
        .any(|root| mp.starts_with(root) && mp != *root);
    if !inside_allowed {
        return Err(format!(
            "'{}' is outside the allowed mount roots ({})",
            mp.display(),
            allowed_roots
                .iter()
                .map(|r| r.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(mp)
}

/// True if `path` sits strictly inside one of the allowed roots.
/// Used for unmount lookups where the directory may no longer stat cleanly.
pub fn inside_allowed(path: &Path, allowed_roots: &[PathBuf]) -> bool {
    allowed_roots
        .iter()
        .any(|root| path.starts_with(root) && path != root)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let tmp = std::env::temp_dir().join(format!("fb-policy-test-{}", std::process::id()));
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
        let tmp = std::env::temp_dir().join(format!("fb-policy-sym-{}", std::process::id()));
        let root = tmp.join("root");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let allowed = vec![std::fs::canonicalize(&root).unwrap()];

        // canonicalize resolves the symlink to a path outside the root
        assert!(check_mountpoint(link.to_str().unwrap(), &allowed).is_err());

        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
