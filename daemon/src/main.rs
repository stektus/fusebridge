//! fusebridged — session daemon that performs FUSE mounts on behalf of
//! sandboxed (Flatpak) applications.
//!
//! The daemon owns no privilege of its own: the privileged step is done by
//! the host's regular setuid fusermount3, exactly as it would be in a
//! terminal. What the daemon adds is policy: who may ask (Flatpak apps,
//! identified via /proc/<pid>/root/.flatpak-info), where mounts may land
//! (empty, user-owned directories under allowed roots), verification of the
//! resulting mount, unmount restricted to the daemon's own mounts, and a
//! journal line for every operation.

mod flatpak;
mod mountinfo;
mod policy;

use std::collections::HashMap;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use log::{error, info, warn};
use zbus::interface;

const FUSERMOUNT: &str = "/usr/bin/fusermount3";
/// How long to wait for the mount to appear after spawning fusermount3.
const MOUNT_TIMEOUT: Duration = Duration::from_secs(15);
/// Grace period after fusermount3 exits before declaring the mount missing.
const POST_EXIT_GRACE: Duration = Duration::from_secs(1);

struct MountRecord {
    app_id: String,
    fstype: String,
    source: String,
    /// The fusermount3 child. With -o auto_unmount it stays alive holding
    /// the comm socket; kept here so its stderr pipe is not closed under it
    /// and so the zombie is reaped on unmount.
    child: Child,
}

struct Caller {
    pid: u32,
    app_id: String,
}

struct Bridge {
    allowed_roots: Vec<PathBuf>,
    allow_unsandboxed: bool,
    /// Separate bus connection for credential lookups: calling back into the
    /// serving connection from a handler would deadlock the blocking API.
    creds: zbus::blocking::fdo::DBusProxy<'static>,
    mounts: Mutex<HashMap<PathBuf, MountRecord>>,
}

impl Bridge {
    /// Resolve and authorize the D-Bus caller. Only same-uid processes are
    /// accepted; Flatpak identity is required unless --allow-unsandboxed.
    fn identify_caller(
        &self,
        header: &zbus::message::Header<'_>,
    ) -> Result<Caller, zbus::fdo::Error> {
        let sender = header
            .sender()
            .ok_or_else(|| zbus::fdo::Error::AccessDenied("no sender on message".into()))?;
        let creds = self
            .creds
            .get_connection_credentials(zbus::names::BusName::from(sender.to_owned()))
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot get caller credentials: {e}")))?;
        let pid = creds
            .process_id()
            .ok_or_else(|| zbus::fdo::Error::AccessDenied("caller pid unavailable".into()))?;
        let uid = creds
            .unix_user_id()
            .ok_or_else(|| zbus::fdo::Error::AccessDenied("caller uid unavailable".into()))?;
        if uid != unsafe { libc::geteuid() } {
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "caller uid {uid} does not match session user"
            )));
        }
        match flatpak::app_id_of_pid(pid) {
            Ok(Some(app_id)) => Ok(Caller { pid, app_id }),
            Ok(None) if self.allow_unsandboxed => Ok(Caller {
                pid,
                app_id: "(unsandboxed)".into(),
            }),
            Ok(None) => Err(zbus::fdo::Error::AccessDenied(
                "caller is not a Flatpak application".into(),
            )),
            Err(e) => Err(zbus::fdo::Error::Failed(format!(
                "cannot inspect caller (pid {pid}): {e}"
            ))),
        }
    }

    /// Drop state records whose mounts no longer exist (e.g. the FUSE
    /// process died and the kernel cleaned up, or auto_unmount fired).
    fn sweep_stale(&self, mounts: &mut HashMap<PathBuf, MountRecord>) {
        mounts.retain(|mp, rec| match mountinfo::find(mp) {
            Ok(Some(_)) => true,
            _ => {
                let _ = rec.child.try_wait();
                info!(
                    "sweep: mount at '{}' (app {}) is gone, dropping record",
                    mp.display(),
                    rec.app_id
                );
                false
            }
        });
    }
}

#[interface(name = "io.github.stektus.FuseBridge1")]
impl Bridge {
    /// Perform a FUSE mount. `comm_fd` is the _FUSE_COMMFD unix socket of
    /// the in-sandbox FUSE library; the host fusermount3 sends the /dev/fuse
    /// fd back over it, so the filesystem daemon never leaves the sandbox.
    fn mount(
        &self,
        options: Vec<String>,
        mountpoint: String,
        comm_fd: zbus::zvariant::OwnedFd,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let caller = self.identify_caller(&header)?;
        let deny = |reason: String| {
            warn!(
                "DENY mount app={} pid={} mountpoint='{}': {}",
                caller.app_id, caller.pid, mountpoint, reason
            );
            zbus::fdo::Error::AccessDenied(reason)
        };

        policy::check_options(&options).map_err(&deny)?;
        let mp = policy::check_mountpoint(&mountpoint, &self.allowed_roots).map_err(&deny)?;

        let mut mounts = self.mounts.lock().unwrap();
        self.sweep_stale(&mut mounts);
        if mounts.contains_key(&mp) {
            return Err(deny(format!(
                "'{}' is already mounted via this daemon",
                mp.display()
            )));
        }
        if mountinfo::find(&mp)
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot read mountinfo: {e}")))?
            .is_some()
        {
            return Err(deny(format!("'{}' is already a mountpoint", mp.display())));
        }

        info!(
            "mount request app={} pid={} mountpoint='{}' options='{}'",
            caller.app_id,
            caller.pid,
            mp.display(),
            options.join(",")
        );

        // Spawn the host's fusermount3 with the sandbox's comm socket.
        // The fd has CLOEXEC set; clear it in the child only (pre_exec runs
        // after fork), so it never leaks into unrelated children.
        let raw_fd = comm_fd.as_raw_fd();
        let mut cmd = Command::new(FUSERMOUNT);
        if !options.is_empty() {
            cmd.arg("-o").arg(options.join(","));
        }
        cmd.arg("--")
            .arg(&mp)
            .env("_FUSE_COMMFD", raw_fd.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(raw_fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot run {FUSERMOUNT}: {e}")))?;

        // Wait until the mount shows up (success), fusermount3 fails, or we
        // time out. fusermount3 exits immediately after a plain mount but
        // stays alive for auto_unmount, so child exit alone decides nothing.
        let deadline = Instant::now() + MOUNT_TIMEOUT;
        let mut exited_at: Option<(std::process::ExitStatus, Instant)> = None;
        let entry = loop {
            if exited_at.is_none() {
                if let Ok(Some(status)) = child.try_wait() {
                    exited_at = Some((status, Instant::now()));
                }
            }
            if let Some(entry) = mountinfo::find(&mp)
                .map_err(|e| zbus::fdo::Error::Failed(format!("cannot read mountinfo: {e}")))?
            {
                break entry;
            }
            if let Some((status, at)) = &exited_at {
                if !status.success() || at.elapsed() > POST_EXIT_GRACE {
                    let mut msg = String::new();
                    if let Some(mut err) = child.stderr.take() {
                        let _ = err.read_to_string(&mut msg);
                    }
                    let msg = msg.trim();
                    error!(
                        "mount FAILED app={} mountpoint='{}' fusermount3 status={} stderr='{}'",
                        caller.app_id,
                        mp.display(),
                        status,
                        msg
                    );
                    return Err(zbus::fdo::Error::Failed(format!(
                        "fusermount3 failed ({status}): {msg}"
                    )));
                }
            } else if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(zbus::fdo::Error::Failed(
                    "timed out waiting for the mount to appear".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        };

        // Post-mount verification (anti-TOCTOU): what actually got mounted
        // must be a FUSE filesystem exactly at the approved path.
        if !entry.fstype.starts_with("fuse") {
            error!(
                "mount VERIFY FAILED app={} mountpoint='{}': fstype '{}' is not FUSE, unmounting",
                caller.app_id,
                mp.display(),
                entry.fstype
            );
            let _ = Command::new(FUSERMOUNT)
                .arg("-u")
                .arg("-z")
                .arg("--")
                .arg(&mp)
                .status();
            let _ = child.kill();
            let _ = child.wait();
            return Err(zbus::fdo::Error::Failed(format!(
                "mounted filesystem type '{}' failed verification",
                entry.fstype
            )));
        }

        info!(
            "mount OK app={} pid={} mountpoint='{}' fstype={} source='{}'",
            caller.app_id,
            caller.pid,
            mp.display(),
            entry.fstype,
            entry.source
        );
        mounts.insert(
            mp,
            MountRecord {
                app_id: caller.app_id,
                fstype: entry.fstype,
                source: entry.source,
                child,
            },
        );
        Ok(())
    }

    /// Unmount a mount previously created through this daemon. Only the
    /// same app id may unmount (unsandboxed callers only in testing mode).
    fn unmount(
        &self,
        mountpoint: String,
        lazy: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let caller = self.identify_caller(&header)?;

        // A dead FUSE endpoint may not canonicalize; fall back to the raw
        // path if it matches a record exactly.
        let mp = std::fs::canonicalize(&mountpoint).unwrap_or_else(|_| PathBuf::from(&mountpoint));
        if !policy::inside_allowed(&mp, &self.allowed_roots) {
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "'{}' is outside the allowed mount roots",
                mp.display()
            )));
        }

        let mut mounts = self.mounts.lock().unwrap();
        let Some(record) = mounts.get(&mp) else {
            warn!(
                "DENY unmount app={} pid={} mountpoint='{}': not a mount of this daemon",
                caller.app_id,
                caller.pid,
                mp.display()
            );
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "'{}' was not mounted through this daemon",
                mp.display()
            )));
        };
        if record.app_id != caller.app_id {
            warn!(
                "DENY unmount app={} pid={} mountpoint='{}': mount belongs to app {}",
                caller.app_id,
                caller.pid,
                mp.display(),
                record.app_id
            );
            return Err(zbus::fdo::Error::AccessDenied(
                "mount belongs to a different application".into(),
            ));
        }

        // Already gone? Just drop the record.
        if mountinfo::find(&mp)
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot read mountinfo: {e}")))?
            .is_none()
        {
            let mut rec = mounts.remove(&mp).unwrap();
            let _ = rec.child.try_wait();
            info!(
                "unmount app={} mountpoint='{}': already gone, record dropped",
                caller.app_id,
                mp.display()
            );
            return Ok(());
        }

        let mut cmd = Command::new(FUSERMOUNT);
        cmd.arg("-u");
        if lazy {
            cmd.arg("-z");
        }
        let output = cmd
            .arg("--")
            .arg(&mp)
            .output()
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot run {FUSERMOUNT}: {e}")))?;
        if !output.status.success() {
            let msg = String::from_utf8_lossy(&output.stderr);
            let msg = msg.trim();
            error!(
                "unmount FAILED app={} mountpoint='{}': {} {}",
                caller.app_id,
                mp.display(),
                output.status,
                msg
            );
            return Err(zbus::fdo::Error::Failed(format!(
                "fusermount3 -u failed ({}): {msg}",
                output.status
            )));
        }

        let mut rec = mounts.remove(&mp).unwrap();
        // fusermount3 with auto_unmount notices the unmount and exits.
        std::thread::sleep(Duration::from_millis(100));
        let _ = rec.child.try_wait();
        info!(
            "unmount OK app={} pid={} mountpoint='{}'",
            caller.app_id,
            caller.pid,
            mp.display()
        );
        Ok(())
    }

    /// List active mounts as (mountpoint, app_id, fstype, source).
    fn list_mounts(&self) -> Vec<(String, String, String, String)> {
        let mut mounts = self.mounts.lock().unwrap();
        self.sweep_stale(&mut mounts);
        mounts
            .iter()
            .map(|(mp, r)| {
                (
                    mp.display().to_string(),
                    r.app_id.clone(),
                    r.fstype.clone(),
                    r.source.clone(),
                )
            })
            .collect()
    }

    #[zbus(property)]
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").into()
    }
}

fn print_usage() {
    eprintln!(
        "usage: fusebridged [--allow-root <dir>]... [--allow-unsandboxed] [--no-default-root]\n\
         \n\
         Mountpoints are allowed only strictly inside the allowed roots\n\
         (default: ~/CloudDrives, created if missing)."
    );
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let mut allowed_roots: Vec<PathBuf> = Vec::new();
    let mut allow_unsandboxed = false;
    let mut default_root = true;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow-root" => {
                let Some(dir) = args.next() else {
                    print_usage();
                    std::process::exit(2);
                };
                match std::fs::canonicalize(&dir) {
                    Ok(p) => allowed_roots.push(p),
                    Err(e) => {
                        error!("--allow-root '{dir}': {e}");
                        std::process::exit(2);
                    }
                }
            }
            "--allow-unsandboxed" => allow_unsandboxed = true,
            "--no-default-root" => default_root = false,
            "-h" | "--help" => {
                print_usage();
                return;
            }
            other => {
                error!("unknown argument '{other}'");
                print_usage();
                std::process::exit(2);
            }
        }
    }

    if default_root {
        match std::env::var_os("HOME") {
            Some(home) => {
                let root = PathBuf::from(home).join("CloudDrives");
                if let Err(e) = std::fs::create_dir_all(&root) {
                    error!("cannot create default root '{}': {e}", root.display());
                    std::process::exit(1);
                }
                match std::fs::canonicalize(&root) {
                    Ok(p) => allowed_roots.push(p),
                    Err(e) => {
                        error!("cannot resolve default root: {e}");
                        std::process::exit(1);
                    }
                }
            }
            None => warn!("HOME is not set; no default mount root"),
        }
    }
    if allowed_roots.is_empty() {
        error!("no allowed mount roots configured");
        std::process::exit(1);
    }
    for root in &allowed_roots {
        info!("allowed mount root: {}", root.display());
    }
    if allow_unsandboxed {
        warn!("--allow-unsandboxed is set: non-Flatpak callers will be accepted (testing mode)");
    }

    let creds_conn = zbus::blocking::Connection::session().unwrap_or_else(|e| {
        error!("cannot connect to session bus: {e}");
        std::process::exit(1);
    });
    let creds = zbus::blocking::fdo::DBusProxy::new(&creds_conn).unwrap_or_else(|e| {
        error!("cannot create bus proxy: {e}");
        std::process::exit(1);
    });

    let bridge = Bridge {
        allowed_roots,
        allow_unsandboxed,
        creds,
        mounts: Mutex::new(HashMap::new()),
    };

    let _conn = zbus::blocking::connection::Builder::session()
        .and_then(|b| b.name(fusebridge_proto::BUS_NAME))
        .and_then(|b| b.serve_at(fusebridge_proto::OBJECT_PATH, bridge))
        .and_then(|b| b.build())
        .unwrap_or_else(|e| {
            error!("cannot claim {}: {e}", fusebridge_proto::BUS_NAME);
            std::process::exit(1);
        });

    info!(
        "fusebridged {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        fusebridge_proto::BUS_NAME
    );
    loop {
        std::thread::park();
    }
}
