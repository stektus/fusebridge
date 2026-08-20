//! Identify the calling process as a Flatpak app via its `.flatpak-info`.
//!
//! The file lives at the root of the caller's mount namespace, reachable
//! from outside as `/proc/<pid>/root/.flatpak-info`. Everything is read
//! through a single descriptor on `/proc/<pid>`, opened once: if the pid is
//! recycled between the credential lookup and the read, that descriptor
//! refers to the dead process and the read fails, rather than silently
//! describing whichever process inherited the number.
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
use std::os::fd::AsRawFd;
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

/// Read the caller's `.flatpak-info`.
///
/// `Ok(Some(app_id))` for a sandboxed caller, `Ok(None)` when the file does
/// not exist (the caller is not a Flatpak app), `Err` on other failures.
pub fn app_id_of_pid(pid: u32) -> std::io::Result<Option<String>> {
    let proc_dir = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}"))?;
    let path = format!("/proc/self/fd/{}/root/.flatpak-info", proc_dir.as_raw_fd());
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(Some(
            parse_app_id(&content).unwrap_or_else(|| "unknown".into()),
        )),
        // NotFound: no such file, i.e. not a Flatpak app.
        // ESRCH: the process died and the pinned procfs entry went stale.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(app_id_of_pid(std::process::id()).unwrap(), None);
    }

    #[test]
    fn dead_pid_is_an_error_not_an_identity() {
        // Pid 2^22 is above the usual pid_max and never exists.
        assert!(app_id_of_pid(4_194_304).is_err());
    }
}
