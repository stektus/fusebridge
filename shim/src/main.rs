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
    help: bool,
    /// `--auto-unmount` with no mount options: libfuse's *other* auto-unmount
    /// arrangement, where it has already mounted by itself and wants the
    /// helper to hang around as a watchdog. See `run`.
    watchdog: bool,
    /// `--sync-init`: libfuse's two-phase mount, where the helper hands over
    /// `/dev/fuse` first, waits to be told the filesystem has answered
    /// FUSE_INIT, and only then attaches the mount. Recognised so the refusal
    /// can say what it is; see `run`.
    sync_init: bool,
    options: Vec<String>,
    mountpoint: Option<String>,
}

/// Parse the way `fusermount3` does, long options included.
///
/// Its `--help` lists only the short forms, but the long ones work
/// (`--unmount --lazy -- x` behaves exactly like `-u -z -- x`, checked on
/// 3.18.2) and libfuse uses them: unmounting is
/// `--unmount --quiet --lazy -- <mountpoint>`, and that is the path a
/// sandboxed application takes, since it is only reached after its own
/// `umount2` was refused. An unrecognised option is an error here, as it is
/// there — the previous catch-all quietly took `--unmount` for a mountpoint
/// and turned an unmount request into a mount request.
fn parse_args<I: Iterator<Item = String>>(mut it: I) -> Result<Args, String> {
    let mut args = Args::default();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--" => {
                if let Some(mp) = it.next() {
                    args.mountpoint = Some(mp);
                }
            }
            "-h" | "--help" => args.help = true,
            "-V" | "--version" => args.version = true,
            "-u" | "--unmount" => args.unmount = true,
            "-q" | "--quiet" => args.quiet = true,
            "-z" | "--lazy" => args.lazy = true,
            "--auto-unmount" => args.watchdog = true,
            "--sync-init" => args.sync_init = true,
            "-o" | "--options" => {
                let val = it.next().ok_or("-o requires an argument")?;
                args.options.extend(val.split(',').map(String::from));
            }
            s if s.starts_with("--options=") => {
                args.options
                    .extend(s["--options=".len()..].split(',').map(String::from));
            }
            s if s.starts_with("-o") && s.len() > 2 => {
                args.options.extend(s[2..].split(',').map(String::from));
            }
            s if s.starts_with("--") => return Err(format!("unrecognized option '{s}'")),
            s if s.starts_with('-') && s.len() > 1 => {
                for c in s.chars().skip(1) {
                    match c {
                        'u' => args.unmount = true,
                        'z' => args.lazy = true,
                        'q' => args.quiet = true,
                        'V' => args.version = true,
                        'h' => args.help = true,
                        other => return Err(format!("unsupported option '-{other}'")),
                    }
                }
            }
            other => args.mountpoint = Some(other.to_string()),
        }
    }
    // `--auto-unmount` together with mount options is an ordinary mount that
    // also wants cleanup — the flag spelling of the `auto_unmount` mount
    // option, which the daemon implements. Only the bare form, with nothing
    // to mount, is the watchdog arrangement. libfuse only ever emits the
    // bare form, but the helper accepts both and so does this.
    if args.watchdog && !args.options.is_empty() {
        args.watchdog = false;
        args.options.push("auto_unmount".to_string());
    }
    Ok(args)
}

fn call_error_message(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, Some(msg), _) => format!("{msg} [{name}]"),
        other => other.to_string(),
    }
}

const USAGE: &str = "fusermount3 (fusebridge-shim): [options] mountpoint\n\
     Options:\n\
     \x20-h, --help             print help\n\
     \x20-V, --version          print version\n\
     \x20-o, --options opt[,opt...]  mount options\n\
     \x20-u, --unmount          unmount\n\
     \x20-q, --quiet            quiet\n\
     \x20-z, --lazy             lazy unmount";

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args().skip(1)).map_err(|e| format!("{e}\n{USAGE}"))?;

    if args.version {
        println!(
            "fusermount3 version: {} (fusebridge-shim, forwards to {})",
            env!("CARGO_PKG_VERSION"),
            BUS_NAME
        );
        return Ok(());
    }

    if args.help {
        println!("{USAGE}");
        return Ok(());
    }

    // The two-phase protocol that arrives with libfuse's new mount API. It
    // is not implemented here, and declining is safe rather than fatal:
    // libfuse falls back to the classic helper protocol on any failure of
    // this path (fuse_session_mount, "fall back to old API"), and that is the
    // protocol the bridge speaks. Declining by name, quickly, is what makes
    // the fallback prompt — the socket closes, so libfuse sees end-of-file
    // instead of waiting.
    if args.sync_init {
        return Err(
            "--sync-init asks for the two-phase mount protocol, which this bridge does not \
             implement yet. libfuse falls back to the classic helper protocol, \
             which it does."
                .into(),
        );
    }

    // libfuse asks for this only after it has mounted by itself — a
    // privileged path, which is not the one a sandbox takes. The bridge did
    // not make that mount, and it removes only mounts it made, so promising
    // to clean it up would be a promise it cannot keep. Say so instead.
    if args.watchdog {
        return Err(
            "--auto-unmount without mount options asks this helper to watch over a mount \
             somebody else made. The bridge removes only the mounts it made itself, so it \
             will not do that. (A mount made through the bridge gets the same behaviour \
             from the 'auto_unmount' mount option.)"
                .into(),
        );
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

/// Whether errors should be swallowed, decided without parsing: the parse
/// may itself be what failed. `--quiet` counts, which is the spelling
/// libfuse uses when unmounting.
fn wants_quiet<I: Iterator<Item = String>>(mut args: I) -> bool {
    args.any(|a| a == "--quiet" || (a.starts_with('-') && !a.starts_with("--") && a.contains('q')))
}

fn main() -> ExitCode {
    let quiet = wants_quiet(std::env::args().skip(1));
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

    /// The form libfuse 3.18.2 actually uses to unmount, and the one a
    /// sandboxed application reaches, since it is only tried after its own
    /// `umount2` was refused. Taken for a mountpoint, it turned an unmount
    /// into a mount.
    #[test]
    fn libfuse_long_unmount_form() {
        // libfuse: fusermount3 --unmount --quiet --lazy -- /mnt/point
        let a = parse(&["--unmount", "--quiet", "--lazy", "--", "/mnt/point"]);
        assert!(a.unmount, "an unmount request must not become a mount");
        assert!(a.quiet && a.lazy);
        assert!(a.options.is_empty());
        assert_eq!(a.mountpoint.as_deref(), Some("/mnt/point"));
    }

    /// libfuse's other auto-unmount arrangement: it mounted by itself and
    /// wants the helper as a watchdog. Nothing to mount, so no options.
    /// The fifth invocation form, from libfuse's new mount API. The shim has
    /// to name it rather than meet it as an unknown option: the refusal is
    /// what makes libfuse fall back to the protocol the bridge does speak,
    /// and it must be recognised as a form in its own right, not mistaken
    /// for a mountpoint.
    #[test]
    fn libfuse_sync_init_form_is_declined_by_name() {
        let a = parse_args(
            ["--sync-init", "-o", "rw,nosuid", "--", "/mnt/x"]
                .iter()
                .map(|s| s.to_string()),
        )
        .expect("the form must parse, so that it can be declined deliberately");
        assert!(a.sync_init, "--sync-init must be recognised");
        assert_eq!(a.mountpoint.as_deref(), Some("/mnt/x"));
        assert_eq!(a.options, vec!["rw", "nosuid"]);
    }

    #[test]
    fn libfuse_watchdog_form() {
        // libfuse: fusermount3 --auto-unmount -- /mnt/point
        let a = parse(&["--auto-unmount", "--", "/mnt/point"]);
        assert!(a.watchdog, "the watchdog form must be recognised as such");
        assert!(!a.unmount);
        assert!(a.options.is_empty());
        assert_eq!(a.mountpoint.as_deref(), Some("/mnt/point"));
    }

    /// With options it is an ordinary mount that also wants cleanup, which
    /// is the mount option the daemon implements.
    #[test]
    fn auto_unmount_flag_with_options_is_the_mount_option() {
        let a = parse(&["--auto-unmount", "-o", "rw", "--", "/mnt/point"]);
        assert!(!a.watchdog);
        assert_eq!(a.options, vec!["rw", "auto_unmount"]);
    }

    #[test]
    fn long_option_forms() {
        assert_eq!(
            parse(&["--options", "rw,ro", "--", "/m"]).options,
            ["rw", "ro"]
        );
        assert_eq!(
            parse(&["--options=rw,ro", "--", "/m"]).options,
            ["rw", "ro"]
        );
        assert!(parse(&["--version"]).version);
        assert!(parse(&["--help"]).help);
        assert!(parse(&["-h"]).help);
    }

    /// The real helper answers `unrecognized option '--x'` and fails; a
    /// catch-all that took it for a mountpoint is how the unmount bug got in.
    #[test]
    fn quiet_is_honoured_in_both_spellings() {
        let q = |v: &[&str]| wants_quiet(v.iter().map(|s| s.to_string()));
        assert!(q(&["--unmount", "--quiet", "--lazy"]));
        assert!(q(&["-u", "-q", "-z"]));
        assert!(q(&["-uqz"]));
        assert!(!q(&["--unmount", "--lazy"]));
        assert!(!q(&["-o", "quiet_is_not_a_flag_here", "--", "/m"]));
    }

    #[test]
    fn unknown_long_flag_is_rejected_not_taken_for_a_mountpoint() {
        let err = parse_args(["--totally-bogus"].iter().map(|s| s.to_string())).unwrap_err();
        assert!(err.contains("unrecognized option"), "{err}");
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
