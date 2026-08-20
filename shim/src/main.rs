//! fusebridge-shim — installed inside the sandbox as /app/bin/fusermount3.
//!
//! FUSE libraries (libfuse, go-fuse, bazil/fuse — hence rclone, borg,
//! gocryptfs, ...) mount by exec'ing `fusermount3` with the `_FUSE_COMMFD`
//! environment variable pointing at a unix socket, over which they expect
//! the opened /dev/fuse fd back. This shim speaks that exact protocol on
//! one side and the fusebridge D-Bus interface on the other, so the
//! application needs no changes at all.

use std::os::fd::BorrowedFd;
use std::process::ExitCode;

use fusebridge_proto::{BUS_NAME, COMMFD_ENV, INTERFACE, OBJECT_PATH};

#[derive(Debug, Default, PartialEq)]
struct Args {
    unmount: bool,
    lazy: bool,
    quiet: bool,
    version: bool,
    options: Vec<String>,
    mountpoint: Option<String>,
}

fn parse_args<I: Iterator<Item = String>>(mut it: I) -> Result<Args, String> {
    let mut args = Args::default();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--" => {
                if let Some(mp) = it.next() {
                    args.mountpoint = Some(mp);
                }
            }
            "--version" => args.version = true,
            "-o" => {
                let val = it.next().ok_or("-o requires an argument")?;
                args.options.extend(val.split(',').map(String::from));
            }
            s if s.starts_with("-o") => {
                args.options.extend(s[2..].split(',').map(String::from));
            }
            s if s.starts_with('-') && s.len() > 1 && !s.starts_with("--") => {
                for c in s.chars().skip(1) {
                    match c {
                        'u' => args.unmount = true,
                        'z' => args.lazy = true,
                        'q' => args.quiet = true,
                        'V' => args.version = true,
                        other => return Err(format!("unsupported option '-{other}'")),
                    }
                }
            }
            other => args.mountpoint = Some(other.to_string()),
        }
    }
    Ok(args)
}

fn call_error_message(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, Some(msg), _) => format!("{msg} [{name}]"),
        other => other.to_string(),
    }
}

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args().skip(1)).map_err(|e| format!("{e}\nusage: fusermount3 [-o opts] [--] mountpoint | fusermount3 -u [-z] [-q] [--] mountpoint"))?;

    if args.version {
        println!(
            "fusermount3 version: {} (fusebridge-shim, forwards to {})",
            env!("CARGO_PKG_VERSION"),
            BUS_NAME
        );
        return Ok(());
    }

    let mountpoint = args.mountpoint.clone().ok_or("no mountpoint given")?;
    // Resolve to an absolute path inside the sandbox; for shared paths
    // (e.g. --filesystem=home) it is the same path the host sees. A dead
    // FUSE mountpoint may fail to resolve — pass it through for unmount.
    let mountpoint = std::fs::canonicalize(&mountpoint)
        .map(|p| p.display().to_string())
        .unwrap_or(mountpoint);

    let conn = zbus::blocking::Connection::session()
        .map_err(|e| format!("cannot connect to the session bus: {e}"))?;
    let proxy = zbus::blocking::Proxy::new(&conn, BUS_NAME, OBJECT_PATH, INTERFACE)
        .map_err(|e| e.to_string())?;

    if args.unmount {
        proxy
            .call::<_, _, ()>("Unmount", &(mountpoint, args.lazy))
            .map_err(|e| format!("unmount refused: {}", call_error_message(&e)))?;
        return Ok(());
    }

    let comm_fd: i32 = std::env::var(COMMFD_ENV)
        .map_err(|_| {
            format!(
                "{COMMFD_ENV} is not set. This fusermount3 is the fusebridge shim; \
                 it only supports being called by a FUSE library, not direct mounting."
            )
        })?
        .parse()
        .map_err(|e| format!("bad {COMMFD_ENV} value: {e}"))?;
    // SAFETY: the fd was inherited from the FUSE library across exec and
    // stays open for the lifetime of this short-lived process.
    let comm_fd = unsafe { BorrowedFd::borrow_raw(comm_fd) };

    proxy
        .call::<_, _, ()>(
            "Mount",
            &(&args.options, mountpoint, zbus::zvariant::Fd::from(comm_fd)),
        )
        .map_err(|e| format!("mount refused: {}", call_error_message(&e)))?;
    Ok(())
}

fn main() -> ExitCode {
    let quiet = std::env::args()
        .skip(1)
        .any(|a| a == "-q" || (a.starts_with('-') && !a.starts_with("--") && a.contains('q')));
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            if !quiet {
                eprintln!("fusermount3 (fusebridge-shim): {msg}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: &[&str]) -> Args {
        parse_args(v.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn libfuse_mount_form() {
        // libfuse: fusermount3 -o rw,nosuid -- /mnt/point
        let a = parse(&["-o", "rw,nosuid,fsname=x", "--", "/mnt/point"]);
        assert!(!a.unmount);
        assert_eq!(a.options, vec!["rw", "nosuid", "fsname=x"]);
        assert_eq!(a.mountpoint.as_deref(), Some("/mnt/point"));
    }

    #[test]
    fn bazil_mount_form() {
        // bazil/fuse: fusermount -o opts -- dir
        let a = parse(&["-o", "ro", "--", "dir"]);
        assert_eq!(a.options, vec!["ro"]);
        assert_eq!(a.mountpoint.as_deref(), Some("dir"));
    }

    #[test]
    fn libfuse_unmount_form() {
        // libfuse: fusermount3 -u -q -z -- /mnt/point
        let a = parse(&["-u", "-q", "-z", "--", "/mnt/point"]);
        assert!(a.unmount && a.quiet && a.lazy);
        assert_eq!(a.mountpoint.as_deref(), Some("/mnt/point"));
    }

    #[test]
    fn clustered_flags_and_bare_mountpoint() {
        let a = parse(&["-uz", "/m"]);
        assert!(a.unmount && a.lazy && !a.quiet);
        assert_eq!(a.mountpoint.as_deref(), Some("/m"));
    }

    #[test]
    fn attached_o_value() {
        let a = parse(&["-orw,dev", "/m"]);
        assert_eq!(a.options, vec!["rw", "dev"]);
    }

    #[test]
    fn version_flag() {
        assert!(parse(&["--version"]).version);
        assert!(parse(&["-V"]).version);
    }

    #[test]
    fn unknown_flag_rejected() {
        assert!(parse_args(["-x"].iter().map(|s| s.to_string())).is_err());
    }
}
