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
use std::sync::{Arc, Mutex};
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
/// How long to spend resolving a mountpoint before giving up on it.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for a mount to say whether it is still connected. A
/// mount that has been abandoned answers at once; one that is still alive
/// but unserved never answers, and is not ours to touch anyway.
const LIVENESS_TIMEOUT: Duration = Duration::from_millis(500);
/// Attempts to remove a mount that must not stay, and the pause between them.
const REVERT_ATTEMPTS: usize = 40;
const REVERT_PAUSE: Duration = Duration::from_millis(50);
/// How long to keep looking for a mount that went astray, and how often.
/// The helper can still be attaching it while this thread reads the table,
/// so a single reading that shows nothing is not evidence that nothing
/// happened — and concluding otherwise leaves the stray mount in place.
const STRAY_WATCH: Duration = Duration::from_secs(2);
const STRAY_POLL: Duration = Duration::from_millis(25);

struct MountRecord {
    app_id: String,
    fstype: String,
    source: String,
    /// The fusermount3 child, kept so its zombie is reaped on unmount and so
    /// its stderr pipe is not closed under it if it is still running.
    child: Child,
    /// The daemon's end of the socket fusermount3 reported on. Kept for the
    /// life of the mount: a helper that is still watching it must not see it
    /// close early.
    _comm: OwnedFd,
    /// Write end of the pipe that tells an `auto_unmount` watcher to stop.
    /// Dropping this record closes it, which is the signal — so a mount
    /// removed any other way does not leave a thread behind.
    _watcher_stop: Option<OwnedFd>,
}

struct Caller {
    pid: u32,
    app_id: String,
}

/// What the daemon knows about mounts: the ones it made, and the mountpoints
/// it is in the middle of making. Requests run on worker threads, so both
/// have to be decided together, under one lock.
#[derive(Default)]
struct Registry {
    mounts: HashMap<PathBuf, MountRecord>,
    in_progress: HashSet<PathBuf>,
}

struct State {
    allowed_roots: Vec<PathBuf>,
    allow_unsandboxed: bool,
    max_mounts: usize,
    /// Separate bus connection for credential lookups: calling back into the
    /// serving connection from a handler would deadlock the blocking API.
    creds: zbus::blocking::fdo::DBusProxy<'static>,
    registry: Mutex<Registry>,
}

/// The D-Bus face of the daemon.
///
/// Each call is handed to a worker thread. The work is blocking by nature —
/// resolving a path, running a helper, waiting for a mount to appear — and
/// doing it on the connection's own thread would mean one application's
/// mount keeps every other application waiting.
struct Bridge {
    state: Arc<State>,
}

/// Releases a reserved mountpoint however the request ends.
struct Reservation {
    state: Arc<State>,
    path: PathBuf,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.state
            .registry
            .lock()
            .unwrap()
            .in_progress
            .remove(&self.path);
    }
}

impl State {
    /// Resolve and authorize the D-Bus caller. Only same-uid processes are
    /// accepted; Flatpak identity is required unless --allow-unsandboxed.
    ///
    /// Both facts about the caller — its uid and its app id — are read
    /// through one pinned handle on its `/proc` entry, so they cannot come
    /// from two different processes. The bus's own `UnixUserID` is not used
    /// for the decision: it was captured when the connection was made, and
    /// the connection can outlive the process that opened it.
    fn identify_caller(&self, sender: &str) -> Result<Caller, zbus::fdo::Error> {
        let sender = zbus::names::BusName::try_from(sender)
            .map_err(|e| zbus::fdo::Error::Failed(format!("unusable sender name: {e}")))?;
        let creds = self
            .creds
            .get_connection_credentials(sender)
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot get caller credentials: {e}")))?;

        let denied = |e: std::io::Error| zbus::fdo::Error::AccessDenied(format!("caller: {e}"));
        let pinned = match creds.process_fd() {
            Some(pidfd) => flatpak::pin_by_pidfd(pidfd.as_fd()).map_err(denied)?,
            // dbus < 1.16 does not offer a pidfd; warned about once at startup.
            None => {
                let pid = creds.process_id().ok_or_else(|| {
                    zbus::fdo::Error::AccessDenied("caller pid unavailable".into())
                })?;
                flatpak::pin_by_pid(pid).map_err(denied)?
            }
        };
        let pid = pinned.pid();

        let uid = pinned
            .uid()
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot read caller uid: {e}")))?;
        if uid != unsafe { libc::geteuid() } {
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "caller uid {uid} does not match session user"
            )));
        }
        match pinned.app_id() {
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
    ///
    /// Forgetting a mount costs the ability to unmount it later, so a record
    /// is never dropped merely because the mount table could not be read,
    /// and only when the mount is missing from two separate readings.
    fn sweep_stale(&self, mounts: &mut HashMap<PathBuf, MountRecord>) {
        let missing: Vec<PathBuf> = mounts
            .keys()
            .filter(|mp| matches!(mountinfo::find(mp), Ok(None)))
            .cloned()
            .collect();
        for mp in missing {
            if !matches!(mountinfo::find(&mp), Ok(None)) {
                continue;
            }
            if let Some(mut rec) = mounts.remove(&mp) {
                let _ = rec.child.try_wait();
                info!(
                    "sweep: mount at '{}' (app {}) is gone, dropping record",
                    mp.display(),
                    rec.app_id
                );
            }
        }
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

    /// Everything that could be the mount this operation caused, going the
    /// wrong way: new since the operation started, on a FUSE connection that
    /// appeared while the helper ran, and not the approved directory.
    ///
    /// Neither test is proof on its own. The mount table belongs to the whole
    /// session, anything may mount at any moment, and the kernel reuses
    /// connection numbers after an abort. This narrows the field; `we_made`
    /// decides.
    fn misplaced_candidates(
        &self,
        before: &HashSet<String>,
        ours: Option<&HashSet<String>>,
        approved: &Path,
    ) -> Vec<PathBuf> {
        mountinfo::fuse_mounts()
            .unwrap_or_default()
            .into_iter()
            .filter(|entry| mountinfo::could_be_from_this_operation(entry, approved, before, ours))
            .map(|entry| entry.mount_point)
            .collect()
    }

    /// The same, but not decided on one instantaneous reading.
    ///
    /// `fusermount3` can still be attaching the mount while this thread
    /// looks, and a reading taken a moment too early shows an empty table —
    /// from which the daemon would conclude that nothing went astray and
    /// leave the stray mount behind for good. So keep looking for a bounded
    /// while. This costs time only on a request that has already failed,
    /// and the descriptor is held throughout, so anything that does turn up
    /// is worthless until it is removed.
    ///
    /// Found by running the attack suite on systems where the first reading
    /// happened to lose that race — it is a race, so it hides as soon as
    /// anything slows the path down.
    fn watch_for_misplaced(
        &self,
        before: &HashSet<String>,
        ours: Option<&HashSet<String>>,
        approved: &Path,
    ) -> Vec<PathBuf> {
        let deadline = Instant::now() + STRAY_WATCH;
        loop {
            let found = self.misplaced_candidates(before, ours, approved);
            if !found.is_empty() || Instant::now() >= deadline {
                return found;
            }
            std::thread::sleep(STRAY_POLL);
        }
    }

    /// Of those candidates, the ones this daemon actually made.
    ///
    /// The proof is what dropping the descriptor did to them. While the
    /// daemon holds it, its own mount is connected, whoever is or is not
    /// serving it; letting go disconnects it. Nothing else in the session
    /// changes at that instant. So the mount that went from connected to
    /// disconnected is ours, and everything else is somebody's business we
    /// have none of:
    ///
    /// * a filesystem being served answers throughout — a document portal or
    ///   an archive mount that happened to start while we worked;
    /// * a filesystem that was *already* disconnected stays that way — some
    ///   other program's mount whose server died on its own. Removing that
    ///   would be tidying up after a stranger, and this daemon has no
    ///   business deciding when a stranger's mount should go.
    ///
    /// `before` must be gathered while the descriptor is still held.
    fn we_made(
        &self,
        candidates: &[PathBuf],
        before: &HashMap<PathBuf, policy::Liveness>,
    ) -> Vec<PathBuf> {
        candidates
            .iter()
            .filter(|path| {
                let was = before
                    .get(*path)
                    .copied()
                    .unwrap_or(policy::Liveness::Silent);
                let now = policy::liveness_within(path, LIVENESS_TIMEOUT);
                if policy::is_ours(was, now) {
                    return true;
                }
                warn!(
                    "a FUSE mount at '{}' appeared during this operation but went from {was:?} \
                     to {now:?}, so it is not ours; leaving it alone",
                    path.display()
                );
                false
            })
            .cloned()
            .collect()
    }

    /// What each of these mounts has to say for itself right now.
    fn liveness_of(&self, candidates: &[PathBuf]) -> HashMap<PathBuf, policy::Liveness> {
        candidates
            .iter()
            .map(|path| {
                (
                    path.clone(),
                    policy::liveness_within(path, LIVENESS_TIMEOUT),
                )
            })
            .collect()
    }

    /// Watch an application's `_FUSE_COMMFD` socket and remove its mount when
    /// the application is gone — what `auto_unmount` asks for.
    ///
    /// The helper cannot do this through the bridge, because the socket it
    /// would watch is the daemon's. The application's own socket is right
    /// here, though: libfuse holds its end open for the life of the session
    /// when `auto_unmount` was requested, so end-of-file on this end means
    /// the application has died, and nothing else does.
    ///
    /// The thread owns both descriptors, so nothing it waits on can be
    /// closed underneath it. It stops either way: on end-of-file it takes
    /// the mount down, and on the record going away — an explicit unmount,
    /// say — the other end of `stop` closes and it simply leaves.
    fn watch_for_exit(self: &Arc<Self>, mp: PathBuf, comm: OwnedFd, stop: OwnedFd) {
        let state = Arc::clone(self);
        std::thread::spawn(move || {
            let mut fds = [
                libc::pollfd {
                    fd: comm.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stop.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            loop {
                // SAFETY: both descriptors are owned by this thread and stay
                // open for the whole call.
                let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    warn!("auto_unmount watcher for '{}' gave up: {err}", mp.display());
                    return;
                }
                if fds[1].revents != 0 {
                    return; // the mount is already gone
                }
                if fds[0].revents == 0 {
                    continue;
                }
                // Readable, or hung up. Only a read of zero proves the far
                // end is gone; anything else is data we have no use for.
                let mut byte = [0u8; 1];
                match fdpass::read_byte(comm.as_fd(), &mut byte) {
                    Ok(0) => break,
                    Ok(_) => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        warn!("auto_unmount watcher for '{}' gave up: {e}", mp.display());
                        return;
                    }
                }
            }

            let record = state.registry.lock().unwrap().mounts.remove(&mp);
            let Some(record) = record else {
                return; // somebody unmounted it first
            };
            // Release the record — and with it the helper's socket — before
            // unmounting, so nothing is still holding the mount open.
            let app_id = record.app_id.clone();
            drop(record);
            if state.force_unmount(&mp) {
                info!(
                    "auto_unmount app={app_id} mountpoint='{}': the application exited",
                    mp.display()
                );
            } else {
                error!(
                    "auto_unmount app={app_id} mountpoint='{}': the application exited but the \
                     mount could not be removed",
                    mp.display()
                );
            }
        });
    }

    /// Remove mounts this operation made that did not land where they should.
    fn remove_misplaced(&self, paths: &[PathBuf]) -> Vec<PathBuf> {
        let mut left_behind = Vec::new();
        for path in paths {
            error!(
                "removing a mount that landed outside the approved directory: '{}'",
                path.display()
            );
            if !self.force_unmount(path) {
                left_behind.push(path.clone());
            }
        }
        left_behind
    }
}

impl State {
    /// Perform a FUSE mount. `comm_fd` is the _FUSE_COMMFD unix socket of
    /// the in-sandbox FUSE library; the host fusermount3 sends the /dev/fuse
    /// fd back over it, so the filesystem daemon never leaves the sandbox.
    fn mount(
        self: &Arc<Self>,
        options: Vec<String>,
        mountpoint: String,
        comm_fd: zbus::zvariant::OwnedFd,
        sender: String,
    ) -> zbus::fdo::Result<()> {
        let caller = self.identify_caller(&sender)?;
        let deny = |reason: String| {
            warn!(
                "DENY mount app={} pid={} mountpoint='{}': {}",
                caller.app_id, caller.pid, mountpoint, reason
            );
            zbus::fdo::Error::AccessDenied(reason)
        };

        policy::check_options(&options).map_err(&deny)?;
        // Taken out of what the helper is given: through the bridge it would
        // watch the daemon's socket, not the application's. The daemon does
        // the watching instead, once the mount is up.
        let auto_unmount = policy::wants_auto_unmount(&options);
        let helper_options = policy::without_auto_unmount(&options);

        // Resolving comes before the lock: it can take a while, and holding
        // the registry meanwhile would make every other request wait.
        // From here on the mountpoint is held open: the descriptor, not the
        // path, is what gets mounted on.
        let approved =
            policy::check_mountpoint_within(&mountpoint, &self.allowed_roots, RESOLVE_TIMEOUT)
                .map_err(&deny)?;
        let mp = approved.path.clone();

        // Claim the mountpoint. Two requests naming the same directory must
        // not both proceed, and the ceiling counts work in flight too.
        let _reservation = {
            let mut registry = self.registry.lock().unwrap();
            self.sweep_stale(&mut registry.mounts);
            if registry.mounts.len() + registry.in_progress.len() >= self.max_mounts {
                return Err(deny(format!(
                    "the limit of {} live mounts is reached",
                    self.max_mounts
                )));
            }
            if registry.mounts.contains_key(&mp) {
                return Err(deny(format!(
                    "'{}' is already mounted via this daemon",
                    mp.display()
                )));
            }
            if !registry.in_progress.insert(mp.clone()) {
                return Err(deny(format!("'{}' is already being mounted", mp.display())));
            }
            Reservation {
                state: Arc::clone(self),
                path: mp.clone(),
            }
        };

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
        let connections_before = mountinfo::fuse_connections().unwrap_or(None);
        let mounts_before: HashSet<String> = mountinfo::fuse_mounts()
            .map_err(|e| zbus::fdo::Error::Failed(format!("cannot read mountinfo: {e}")))?
            .iter()
            .map(mountinfo::MountEntry::key)
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
        if !helper_options.is_empty() {
            cmd.arg("-o").arg(helper_options.join(","));
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
        // `None` all the way through means the kernel is not publishing its
        // connection list, so this narrowing is unavailable rather than empty.
        let new_connections: Option<HashSet<String>> = match (
            connections_before,
            mountinfo::fuse_connections().unwrap_or(None),
        ) {
            (Some(before), Some(now)) => Some(now.difference(&before).cloned().collect()),
            _ => None,
        };

        let landed = policy::fd_path(&approved.dir).ok();
        let verified = entry.as_ref().is_some_and(|e| e.fstype.starts_with("fuse"))
            && landed.as_deref() == Some(mp.as_path())
            && policy::inside_allowed(&mp, &self.allowed_roots)
            && fuse_fd.is_some();

        if !verified {
            // Only go looking for a misplaced mount when nothing appeared at
            // the approved path. If the mount is there and the request failed
            // for some other reason, no mount went astray, and anything else
            // new in the table belongs to somebody else.
            let stuck = if entry.is_none() {
                // Ask who is answering while the descriptor is still held:
                // that is what tells this operation's mount apart from a
                // filesystem somebody else happens to be starting.
                let candidates =
                    self.watch_for_misplaced(&mounts_before, new_connections.as_ref(), &mp);
                let before_drop = self.liveness_of(&candidates);
                drop(fuse_fd);
                let ours = self.we_made(&candidates, &before_drop);
                self.remove_misplaced(&ours)
            } else {
                drop(fuse_fd);
                self.force_unmount(&mp);
                Vec::new()
            };
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

        // Set up the watcher before the mount is announced, so there is no
        // moment where the mount exists and nothing is waiting on the
        // application. If the pipe cannot be made, say so and carry on
        // without it rather than failing a mount that otherwise worked.
        let watcher_stop = if auto_unmount {
            match fdpass::stop_pipe() {
                Ok((stop_r, stop_w)) => {
                    let app_socket = comm_fd.into();
                    self.watch_for_exit(mp.clone(), app_socket, stop_r);
                    Some(stop_w)
                }
                Err(e) => {
                    error!(
                        "auto_unmount app={} mountpoint='{}': cannot watch the application \
                         ({e}); the mount will have to be removed by hand",
                        caller.app_id,
                        mp.display()
                    );
                    None
                }
            }
        } else {
            None
        };

        info!(
            "mount OK app={} pid={} mountpoint='{}' fstype={} source='{}'{}",
            caller.app_id,
            caller.pid,
            mp.display(),
            entry.fstype,
            entry.source,
            if watcher_stop.is_some() {
                " auto_unmount=watching"
            } else {
                ""
            }
        );
        self.registry.lock().unwrap().mounts.insert(
            mp,
            MountRecord {
                app_id: caller.app_id,
                fstype: entry.fstype,
                source: entry.source,
                child,
                _comm: ours,
                _watcher_stop: watcher_stop,
            },
        );
        Ok(())
    }

    /// Unmount a mount previously created through this daemon, by the same
    /// application that created it.
    fn unmount(&self, mountpoint: String, lazy: bool, sender: String) -> zbus::fdo::Result<()> {
        let caller = self.identify_caller(&sender)?;

        // A dead FUSE endpoint may not canonicalize; fall back to the raw
        // path if it matches a record exactly.
        let mp = std::fs::canonicalize(&mountpoint).unwrap_or_else(|_| PathBuf::from(&mountpoint));
        if !policy::inside_allowed(&mp, &self.allowed_roots) {
            return Err(zbus::fdo::Error::AccessDenied(format!(
                "'{}' is outside the allowed mount roots",
                mp.display()
            )));
        }

        let mut registry = self.registry.lock().unwrap();
        let mounts = &mut registry.mounts;
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
        let mut registry = self.registry.lock().unwrap();
        let Registry { mounts, .. } = &mut *registry;
        self.sweep_stale(mounts);
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
}

/// The name of the connection a message came from, which is what the caller
/// is identified by.
fn sender_of(header: &zbus::message::Header<'_>) -> zbus::fdo::Result<String> {
    header
        .sender()
        .map(|s| s.to_string())
        .ok_or_else(|| zbus::fdo::Error::AccessDenied("no sender on message".into()))
}

#[interface(name = "io.github.stektus.FuseBridge1")]
impl Bridge {
    async fn mount(
        &self,
        options: Vec<String>,
        mountpoint: String,
        comm_fd: zbus::zvariant::OwnedFd,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let sender = sender_of(&header)?;
        let state = Arc::clone(&self.state);
        blocking::unblock(move || state.mount(options, mountpoint, comm_fd, sender)).await
    }

    async fn unmount(
        &self,
        mountpoint: String,
        lazy: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let sender = sender_of(&header)?;
        let state = Arc::clone(&self.state);
        blocking::unblock(move || state.unmount(mountpoint, lazy, sender)).await
    }

    async fn list_mounts(&self) -> Vec<(String, String, String, String)> {
        let state = Arc::clone(&self.state);
        blocking::unblock(move || state.list_mounts()).await
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

    // Ask the bus about this very connection: if it cannot supply a pidfd,
    // no caller will get one either, and identity rests on a pid the bus
    // captured at connection time. Worth saying out loud once.
    let own_pidfd = creds_conn.unique_name().and_then(|name| {
        let name = zbus::names::BusName::from(name.inner().clone());
        creds
            .get_connection_credentials(name)
            .ok()
            .map(|c| c.process_fd().is_some())
    });
    if !mountinfo::fusectl_mounted() {
        warn!(
            "the kernel is not publishing /sys/fs/fuse/connections (fusectl is not mounted): \
             a mount that lands astray is still made worthless by closing its descriptor, but \
             recognising it to remove it rests on the liveness transition alone"
        );
    }

    if own_pidfd == Some(false) {
        warn!(
            "this bus does not supply caller pidfds (needs dbus >= 1.16): callers are \
             identified by pid, which a caller that hands off its connection and exits \
             can make stale"
        );
    }

    let bridge = Bridge {
        state: Arc::new(State {
            allowed_roots,
            allow_unsandboxed,
            max_mounts,
            creds,
            registry: Mutex::new(Registry::default()),
        }),
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
