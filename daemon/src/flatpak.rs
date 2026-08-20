//! Identify the calling process as a Flatpak app via /proc/<pid>/root/.flatpak-info.

/// Extract the app id from .flatpak-info content ([Application] name=...).
/// A bare `flatpak run <runtime>` shell carries [Runtime] instead — still a
/// sandboxed Flatpak instance, so its name is accepted too.
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

/// Read the caller's .flatpak-info through its /proc root.
/// Returns Ok(Some(app_id)) for a sandboxed caller, Ok(None) when the file
/// does not exist (caller is not a Flatpak app), Err on other I/O failures.
pub fn app_id_of_pid(pid: u32) -> std::io::Result<Option<String>> {
    let path = format!("/proc/{pid}/root/.flatpak-info");
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(Some(
            parse_app_id(&content).unwrap_or_else(|| "unknown".into()),
        )),
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
}
