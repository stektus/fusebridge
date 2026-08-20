//! Identify the calling process as a Flatpak app via its `.flatpak-info`.
//!
//! The file lives at the root of the caller's mount namespace, reachable
//! from outside as `/proc/<pid>/root/.flatpak-info`. Everything is read
//! through a single descriptor on `/proc/<pid>`, opened once: if the pid is
//! recycled between the credential lookup and the read, that descriptor
//! refers to the dead process and the read fails, rather than silently
//! describing whichever process inherited the number.
//!
//! A pid on its own is a number, though, and the bus captured it when the
//! connection was made. A caller can hand its bus socket to another process
//! over `SCM_RIGHTS` and exit: the connection stays open, the bus keeps
//! reporting the pid of a process that no longer exists, and once that
//! number comes round again it names somebody else's application. So the
//! process is pinned by descriptor instead, using the pidfd the bus obtained
//! at the same moment as the pid (`ProcessFD`, dbus >= 1.16). The pid is
//! read from the pidfd, `/proc/<pid>` is opened, and the pidfd is read
//! again: a pidfd whose process has been reaped reports `Pid: -1` for ever
//! after, so a second reading that still names the same pid proves the
//! number was never freed, and therefore never belonged to anyone else.
//!
//! Note what this does and does not prove. A process that can create a user
//! namespace can chroot into a forged root and claim any app id — verified
//! by doing it, including taking over another app's mount. It buys nothing:
//! such a process is unsandboxed, so it can already run `fusermount3`
//! directly. What matters is that the callers this policy governs cannot do
//! it — Flatpak's seccomp filter refuses `unshare(CLONE_NEWUSER)` inside the
//! sandbox, with and without `--devel` (verified on flatpak 1.18.1). So an
//! app id identifies a sandboxed caller, and means nothing from an
//! unsandboxed one.

use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::OpenOptionsExt;

/// Extract the app id from `.flatpak-info` content (`[Application] name=`).
/// A bare `flatpak run <runtime>` shell carries `[Runtime]` instead — still
/// a sandboxed Flatpak instance, so its name is accepted as the id.
pub fn parse_app_id(content: &str) -> Option<String> {
    let mut section = "";
    let mut runtime_name = None;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line;
            continue;
        }
        if let Some(v) = line.strip_prefix("name=") {
            match section {
                "[Application]" => return Some(v.trim().to_string()),
                "[Runtime]" => runtime_name = Some(v.trim().to_string()),
                _ => {}
            }
        }
    }
    runtime_name
}

/// A caller's procfs entry, held open so that it keeps describing the same
/// process for as long as the handle lives — or fails, if that process is
/// gone. It never comes to describe a different one.
#[derive(Debug)]
pub struct Pinned {
    proc_dir: File,
    pid: u32,
}

/// The pid a pidfd refers to, or `None` once that process has been reaped.
///
/// `/proc/self/fdinfo/<pidfd>` carries a `Pid:` line, which the kernel sets
/// to -1 when the process is gone. Verified against Linux 6.18.
fn pid_of_pidfd(pidfd: BorrowedFd<'_>) -> Result<Option<u32>> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    let field = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "no Pid: field, not a pidfd"))?
        .trim();
    if field == "-1" {
        return Ok(None);
    }
    field.parse::<u32>().map(Some).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("bad Pid: field '{field}': {e}"),
        )
    })
}

fn open_proc_dir(pid: u32) -> Result<File> {
    File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}"))
}

/// Pin the process a bus-supplied pidfd refers to.
///
/// The second reading of the pidfd is what makes this exact rather than
/// merely narrow: if it still names the same pid, that pid has not been
/// released since the first reading, so the `/proc` entry opened in between
/// cannot have been anybody else's.
pub fn pin_by_pidfd(pidfd: BorrowedFd<'_>) -> Result<Pinned> {
    let pid = pid_of_pidfd(pidfd)?
        .ok_or_else(|| Error::new(ErrorKind::NotFound, "the calling process is gone"))?;
    let proc_dir = open_proc_dir(pid)?;
    match pid_of_pidfd(pidfd)? {
        Some(again) if again == pid => Ok(Pinned { proc_dir, pid }),
        _ => Err(Error::new(
            ErrorKind::NotFound,
            "the calling process exited while it was being identified",
        )),
    }
}

/// Pin by pid alone, for a bus too old to supply a pidfd (dbus < 1.16).
///
/// The handle is as stable as in the pidfd case, but what it is bound *to*
/// rests on the bus's pid still naming the caller — see the module comment.
pub fn pin_by_pid(pid: u32) -> Result<Pinned> {
    Ok(Pinned {
        proc_dir: open_proc_dir(pid)?,
        pid,
    })
}

impl Pinned {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    fn path(&self, rest: &str) -> String {
        format!("/proc/self/fd/{}/{rest}", self.proc_dir.as_raw_fd())
    }

    /// The effective uid of the pinned process, read from the pinned handle
    /// rather than taken from the bus, so it describes the same process the
    /// app id does.
    pub fn uid(&self) -> Result<u32> {
        let status = std::fs::read_to_string(self.path("status"))?;
        // "Uid:\t<real>\t<effective>\t<saved>\t<fs>"
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|v| v.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "no usable Uid: field in status"))
    }

    /// Read the caller's `.flatpak-info`.
    ///
    /// `Ok(Some(app_id))` for a sandboxed caller, `Ok(None)` when the file
    /// does not exist (the caller is not a Flatpak app), `Err` otherwise.
    pub fn app_id(&self) -> Result<Option<String>> {
        match std::fs::read_to_string(self.path("root/.flatpak-info")) {
            Ok(content) => Ok(Some(
                parse_app_id(&content).unwrap_or_else(|| "unknown".into()),
            )),
            // NotFound: no such file, i.e. not a Flatpak app.
            // ESRCH: the process died and the pinned procfs entry went stale.
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, FromRawFd, OwnedFd, RawFd};

    #[test]
    fn extracts_app_id() {
        let content = "[Application]\nname=org.example.App\nruntime=runtime/x/y/z\n";
        assert_eq!(parse_app_id(content), Some("org.example.App".into()));
    }

    #[test]
    fn ignores_name_outside_application_section() {
        let content = "[Context]\nname=evil\n[Application]\nname=org.real.App\n";
        assert_eq!(parse_app_id(content), Some("org.real.App".into()));
    }

    #[test]
    fn none_when_missing() {
        assert_eq!(parse_app_id("[Instance]\nid=1\n"), None);
    }

    #[test]
    fn runtime_shell_falls_back_to_runtime_name() {
        let content = "[Runtime]\nname=org.freedesktop.Platform\n[Instance]\ninstance-id=1\n";
        assert_eq!(
            parse_app_id(content),
            Some("org.freedesktop.Platform".into())
        );
    }

    #[test]
    fn application_wins_over_runtime() {
        let content = "[Runtime]\nname=org.fd.Platform\n[Application]\nname=org.real.App\n";
        assert_eq!(parse_app_id(content), Some("org.real.App".into()));
    }

    #[test]
    fn this_process_is_not_a_flatpak_app() {
        assert_eq!(
            pin_by_pid(std::process::id()).unwrap().app_id().unwrap(),
            None
        );
    }

    #[test]
    fn dead_pid_is_an_error_not_an_identity() {
        // Pid 2^22 is above the usual pid_max and never exists.
        assert!(pin_by_pid(4_194_304).is_err());
    }

    fn pidfd_open(pid: u32) -> OwnedFd {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
        assert!(raw >= 0, "pidfd_open({pid}): {}", Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(raw as RawFd) }
    }

    #[test]
    fn a_pidfd_pins_this_process() {
        let fd = pidfd_open(std::process::id());
        let pinned = pin_by_pidfd(fd.as_fd()).unwrap();
        assert_eq!(pinned.pid(), std::process::id());
        assert_eq!(pinned.uid().unwrap(), unsafe { libc::geteuid() });
    }

    /// The point of the pidfd: a caller that has exited cannot be identified
    /// by whoever inherits its pid, it is simply refused.
    #[test]
    fn a_pidfd_whose_process_died_is_refused() {
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .unwrap();
        let fd = pidfd_open(child.id());
        assert!(pin_by_pidfd(fd.as_fd()).is_ok(), "alive: should pin");
        child.kill().unwrap();
        child.wait().unwrap();
        let err = pin_by_pidfd(fd.as_fd()).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::NotFound, "{err}");
    }
}
