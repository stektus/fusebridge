//! fusebridged — session daemon that performs FUSE mounts on behalf of
//! sandboxed (Flatpak) applications.
//!
//! The daemon owns no privilege of its own: the privileged step is done by
//! the host's regular setuid fusermount3, exactly as it would be in a
//! terminal. What the daemon adds is policy: who may ask (Flatpak apps,
//! identified via /proc/<pid>/root/.flatpak-info), where mounts may land
//! (empty, user-owned directories under allowed roots, pinned by an open
//! descriptor so the path cannot be swapped underneath), verification of
//! the resulting mount, a cap on how many mounts one app may hold, unmount
//! restricted to the mount's own app, and a journal line per operation.
//!
//! The daemon also stands between `fusermount3` and the application for the
//! `/dev/fuse` descriptor. `fusermount3` resolves the mountpoint path again
//! when it runs (`fuse_mnt_resolve_path` then `chdir`), so a caller that
//! swaps a path component in that instant can still steer the mount
//! elsewhere — no argument the daemon can pass avoids it. Taking the
//! descriptor first removes what such a mount would be worth: it is only
//! handed to the application once the mount is confirmed to be on the
//! approved directory, and otherwise closed, which leaves the stray mount
//! dead (ENOTCONN) and serving nobody until it is removed.

mod fdpass;
mod flatpak;
mod mountinfo;
mod policy;

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
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
/// Default ceiling on live mounts. Mountpoints are a finite resource and
/// each one costs kernel state; without a cap a buggy or hostile app can
/// fill the mount table for the whole session.
const DEFAULT_MAX_MOUNTS: usize = 64;
/// How long to wait for fusermount3 to hand over the /dev/fuse descriptor.
const FD_TIMEOUT: Duration = Duration::from_secs(5);
/// Attempts to remove a mount that must not stay, and the pause between them.
const REVERT_ATTEMPTS: usize = 40;
const REVERT_PAUSE: Duration = Duration::from_millis(50);

struct MountRecord {
    app_id: String,
    fstype: String,
    source: String,
    /// The fusermount3 child. With -o auto_unmount it stays alive holding
    /// the comm socket; kept here so its stderr pipe is not closed under it
    /// and so the zombie is reaped on unmount.
    child: Child,
    /// The daemon's end of that socket. With -o auto_unmount fusermount3
    /// waits for it to close, so it must outlive the mount.
    _comm: OwnedFd,
}

struct Caller {
    pid: u32,
    app_id: String,
}

struct Bridge {
    allowed_roots: Vec<PathBuf>,
    allow_unsandboxed: bool,
    max_mounts: usize,
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

    /// Remove a mount the daemon decided must not stay. Unmounting names a
    /// path, and a path can be swapped just like any other, so this keeps
    /// trying until the mount is actually gone from the table.
    fn force_unmount(&self, path: &Path) -> bool {
        for _ in 0..REVERT_ATTEMPTS {
            match mountinfo::find(path) {
                Ok(None) => return true,
                Ok(Some(_)) => {}
                Err(_) => return false,
            }
            let _ = Command::new(FUSERMOUNT)
                .arg("-u")
                .arg("-z")
                .arg("--")
                .arg(path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            std::thread::sleep(REVERT_PAUSE);
        }
        matches!(mountinfo::find(path), Ok(None))
    }

    /// Remove the mount this operation caused if it did not land on the
    /// approved directory.
    ///
    /// A candidate has to pass three tests, because the mount table belongs
    /// to the whole session and something else may mount at any moment. It
    /// must not have existed before this operation started (`before`); its
    /// connection must have appeared while the helper ran (`ours`) — the
    /// kernel reuses connection numbers after an abort, which is why the
    /// number alone proves nothing; and it must have died when the daemon
    /// dropped the descriptor a moment ago, since a filesystem somebody else
    /// is serving answers normally and is left alone.
    fn revert_misplaced(
        &self,
        before: &HashSet<String>,
        ours: &HashSet<String>,
        approved: &Path,
    ) -> Vec<PathBuf> {
        let mut left_behind = Vec::new();
        for entry in mountinfo::fuse_mounts().unwrap_or_default() {
            if entry.mount_point == approved
                || before.contains(&entry.id)
                || !ours.contains(&entry.dev)
            {
                continue;
            }
            match std::fs::metadata(&entry.mount_point) {
                Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => {}
                _ => {
                    warn!(
                        "a live FUSE mount at '{}' shares a connection number with this \
                         operation but is not ours; leaving it alone",
                        entry.mount_point.display()
                    );
                    continue;
                }
            }
            error!(
                "removing a mount that landed outside the approved directory: '{}'",
                entry.mount_point.display()
            );
            if !self.force_unmount(&entry.mount_point) {
                left_behind.push(entry.mount_point);
            }
        }
        left_behind
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

        let mut mounts = self.mounts.lock().unwrap();
        self.sweep_stale(&mut mounts);
        if mounts.len() >= self.max_mounts {
            return Err(deny(format!(
                "the limit of {} live mounts is reached",
                self.max_mounts
            )));
        }

        // From here on the mountpoint is held open: the descriptor, not the
        // path, is what gets mounted on.
        let approved = policy::check_mountpoint(&mountpoint, &self.allowed_roots).map_err(&deny)?;
        let mp = approved.path.clone();

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

        // Which FUSE connections and mounts exist now, so the ones this
        // operation creates can be named afterwards — and with them, wherever
        // its mount actually landed.
        let connections_before = mountinfo::fuse_connections().unwrap_or_default();
        let mounts_before: HashSet<String> = mountinfo::fuse_mounts()
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot read mountinfo: {e}")))?
            .into_iter()
            .map(|e| e.id)
            .collect();

        // fusermount3 reports to the daemon, not to the application: the
        // descriptor is the daemon's until the mount has been checked.
        let (ours, theirs) = fdpass::socketpair()
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot create a socket pair: {e}")))?;
        fdpass::set_receive_timeout(ours.as_fd(), FD_TIMEOUT)
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot set a socket timeout: {e}")))?;

        // fchdir into the approved directory and mount "." — fusermount3 will
        // still turn that into a path and resolve it again, but it shortens
        // the window in which a swap could matter.
        let dir_fd = approved.dir.as_raw_fd();
        let theirs_raw = theirs.as_raw_fd();
        let mut cmd = Command::new(FUSERMOUNT);
        if !options.is_empty() {
            cmd.arg("-o").arg(options.join(","));
        }
        cmd.arg("--")
            .arg(".")
            .env("_FUSE_COMMFD", theirs_raw.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        unsafe {
            cmd.pre_exec(move || {
                if libc::fchdir(dir_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(theirs_raw, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot run {FUSERMOUNT}: {e}")))?;
        // The daemon's copy of the helper's end must go, or the receive below
        // would never see the end of the stream.
        drop(theirs);

        // Wait until the mount shows up (success), fusermount3 fails, or we
        // time out. fusermount3 exits immediately after a plain mount but
        // stays alive for auto_unmount, so child exit alone decides nothing.
        let deadline = Instant::now() + MOUNT_TIMEOUT;
        let mut exited_at: Option<(std::process::ExitStatus, Instant)> = None;
        let mut entry;
        let mut timed_out = false;
        loop {
            if exited_at.is_none() {
                if let Ok(Some(status)) = child.try_wait() {
                    exited_at = Some((status, Instant::now()));
                }
            }
            entry = mountinfo::find(&mp)
                .map_err(|e| zbus::fdo::Error::Failed(format!("cannot read mountinfo: {e}")))?;
            if entry.is_some() {
                break;
            }
            match &exited_at {
                Some((status, at)) if !status.success() || at.elapsed() > POST_EXIT_GRACE => break,
                None if Instant::now() > deadline => {
                    timed_out = true;
                    break;
                }
                _ => {}
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Take the descriptor whatever happened. Holding it is what makes a
        // misplaced mount worthless: dropping it aborts the connection, so
        // the mount answers ENOTCONN instead of whatever the app would serve.
        let fuse_fd = fdpass::recv_fd(ours.as_fd()).unwrap_or_default();
        let new_connections: HashSet<String> = mountinfo::fuse_connections()
            .unwrap_or_default()
            .difference(&connections_before)
            .cloned()
            .collect();

        let landed = policy::fd_path(&approved.dir).ok();
        let verified = entry.as_ref().is_some_and(|e| e.fstype.starts_with("fuse"))
            && landed.as_deref() == Some(mp.as_path())
            && policy::inside_allowed(&mp, &self.allowed_roots)
            && fuse_fd.is_some();

        if !verified {
            // Order matters: close the descriptor first so the strays can be
            // recognised as ours and are already dead when they are removed.
            drop(fuse_fd);
            let stuck = self.revert_misplaced(&mounts_before, &new_connections, &mp);
            let _ = child.kill();
            let _ = child.wait();

            let mut msg = String::new();
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_string(&mut msg);
            }
            let reason = if timed_out {
                "timed out waiting for the mount to appear".to_string()
            } else if let Some(landed) = &landed {
                if landed != &mp {
                    format!(
                        "the mountpoint moved to '{}' during the mount",
                        landed.display()
                    )
                } else {
                    format!("fusermount3 did not mount: {}", msg.trim())
                }
            } else {
                format!("fusermount3 did not mount: {}", msg.trim())
            };
            error!(
                "mount FAILED app={} mountpoint='{}': {}",
                caller.app_id,
                mp.display(),
                reason
            );
            if !stuck.is_empty() {
                error!(
                    "could not remove misplaced mounts: {}",
                    stuck
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            return Err(zbus::fdo::Error::Failed(reason));
        }

        // Verified: the application may have the descriptor now.
        let entry = entry.expect("verified implies a mount entry");
        let fuse_fd = fuse_fd.expect("verified implies a descriptor");
        if let Err(e) = fdpass::send_fd(comm_fd.as_fd(), fuse_fd.as_fd()) {
            drop(fuse_fd);
            self.force_unmount(&mp);
            let _ = child.kill();
            let _ = child.wait();
            error!(
                "mount FAILED app={} mountpoint='{}': cannot hand over the fuse descriptor: {e}",
                caller.app_id,
                mp.display()
            );
            return Err(zbus::fdo::Error::Failed(format!(
                "cannot hand over the fuse descriptor: {e}"
            )));
        }
        drop(fuse_fd);

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
                _comm: ours,
            },
        );
        Ok(())
    }

    /// Unmount a mount previously created through this daemon, by the same
    /// application that created it.
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
        if !policy::may_unmount(&record.app_id, &caller.app_id) {
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
        "usage: fusebridged [--allow-root <dir>]... [--allow-unsandboxed]\n\
         \x20                  [--no-default-root] [--max-mounts <n>]\n\
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
    let mut max_mounts = DEFAULT_MAX_MOUNTS;

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
            "--max-mounts" => match args.next().map(|v| v.parse::<usize>()) {
                Some(Ok(n)) if n > 0 => max_mounts = n,
                _ => {
                    error!("--max-mounts needs a positive number");
                    std::process::exit(2);
                }
            },
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
        max_mounts,
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
        "fusebridged {} listening on {} (max {} mounts)",
        env!("CARGO_PKG_VERSION"),
        fusebridge_proto::BUS_NAME,
        max_mounts
    );
    loop {
        std::thread::park();
    }
}
