//! Attack tests: every security claim the daemon makes, exercised against
//! a real daemon on a private bus, with real FUSE mounts.
//!
//! The mounts here are made the way a FUSE library makes them — a socket
//! pair, `_FUSE_COMMFD`, and the `/dev/fuse` descriptor coming back — but
//! nothing serves the filesystem afterwards. The received descriptor is
//! closed immediately, which aborts the connection, so a mount left behind
//! by a failing test returns ENOTCONN instead of hanging anything that
//! walks into it.

use std::io::{BufRead, BufReader};
use std::os::fd::{BorrowedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const FUSERMOUNT: &str = "/usr/bin/fusermount3";

/// Real mounts need /dev/fuse and the setuid helper; without them the
/// mounting tests cannot run and say so instead of failing.
fn fuse_available() -> bool {
    Path::new("/dev/fuse").exists() && Path::new(FUSERMOUNT).exists()
}

fn unique_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("fusebridge-test-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::canonicalize(&dir).unwrap()
}

/// A private session bus with a daemon on it, plus a scratch mount root.
struct Fixture {
    bus: Child,
    daemon: Child,
    address: String,
    tmp: PathBuf,
    root: PathBuf,
    log_path: PathBuf,
    /// The `/dev/fuse` descriptors handed over by the daemon. A real
    /// application holds these for as long as it serves the filesystem, and
    /// so does this fixture: a mount nobody holds open is a dead mount, and
    /// dead mounts are exactly what the daemon cleans up after itself, so
    /// dropping them early would make one test's leftovers look like
    /// another's mistake. They are closed in `Drop`, before unmounting.
    served: std::sync::Mutex<Vec<RawFd>>,
}

impl Fixture {
    fn with_args(tag: &str, extra: &[&str]) -> Fixture {
        let tmp = unique_dir(tag);
        let root = tmp.join("root");
        std::fs::create_dir_all(&root).unwrap();

        let mut bus = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("dbus-daemon must be installed to run these tests");
        let mut line = String::new();
        BufReader::new(bus.stdout.as_mut().unwrap())
            .read_line(&mut line)
            .expect("private bus printed no address");
        let address = line.trim().to_string();

        let mut args: Vec<String> = vec![
            "--no-default-root".into(),
            "--allow-root".into(),
            root.display().to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        // The daemon's own account of what it allowed and refused: a failing
        // security test is not much use without it.
        let log_path = tmp.join("daemon.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let daemon = Command::new(env!("CARGO_BIN_EXE_fusebridged"))
            .args(&args)
            .env("DBUS_SESSION_BUS_ADDRESS", &address)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("cannot start fusebridged");

        let fixture = Fixture {
            bus,
            daemon,
            address,
            tmp,
            root,
            log_path,
            served: std::sync::Mutex::new(Vec::new()),
        };
        fixture.await_ready();
        fixture
    }

    fn new(tag: &str) -> Fixture {
        Fixture::with_args(tag, &["--allow-unsandboxed"])
    }

    /// Wait for the daemon to claim its name on the private bus.
    fn await_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(conn) = self.connect() {
                let proxy = zbus::blocking::Proxy::new(
                    &conn,
                    fusebridge_proto::BUS_NAME,
                    fusebridge_proto::OBJECT_PATH,
                    fusebridge_proto::INTERFACE,
                );
                if let Ok(p) = proxy {
                    if p.call::<_, _, Vec<(String, String, String, String)>>("ListMounts", &())
                        .is_ok()
                    {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("daemon did not come up on the private bus");
    }

    fn connect(&self) -> zbus::Result<zbus::blocking::Connection> {
        zbus::blocking::connection::Builder::address(self.address.as_str())?.build()
    }

    fn proxy(&self) -> zbus::blocking::Proxy<'static> {
        let conn = self.connect().expect("cannot connect to the private bus");
        zbus::blocking::Proxy::new_owned(
            conn,
            fusebridge_proto::BUS_NAME,
            fusebridge_proto::OBJECT_PATH,
            fusebridge_proto::INTERFACE,
        )
        .expect("cannot build proxy")
    }

    /// Ask for a mount the way the shim does. On success the `/dev/fuse`
    /// descriptor is received and closed, leaving a dead-but-present mount.
    fn mount(&self, mountpoint: &Path, options: &[&str]) -> Result<(), String> {
        self.mount_str(&mountpoint.display().to_string(), options)
    }

    fn mount_str(&self, mountpoint: &str, options: &[&str]) -> Result<(), String> {
        let (ours, theirs) = socketpair();
        let opts: Vec<String> = options.iter().map(|s| s.to_string()).collect();
        let result = {
            // SAFETY: `theirs` stays open until it is closed below.
            let borrowed = unsafe { BorrowedFd::borrow_raw(theirs) };
            self.proxy()
                .call::<_, _, ()>(
                    "Mount",
                    &(&opts, mountpoint, zbus::zvariant::Fd::from(borrowed)),
                )
                .map_err(|e| error_text(&e))
        };
        // Our own copy must go, or the receive below would never see EOF.
        unsafe { libc::close(theirs) };

        // The daemon has dropped its copy by now, so this either yields the
        // descriptor or ends the stream at once.
        let received = recv_fd(ours);
        if let Some(fd) = received {
            self.served.lock().unwrap().push(fd);
        }
        unsafe { libc::close(ours) };

        // The contract that makes a misplaced mount worthless: a request that
        // was refused must never leave the application holding a descriptor.
        assert_eq!(
            received.is_some(),
            result.is_ok(),
            "a failed mount handed over a fuse descriptor anyway: {result:?}"
        );
        result
    }

    /// Close the handed-over descriptors, the way an application stops
    /// serving before it unmounts. A FUSE mount whose server is still
    /// attached but answering nothing cannot be unmounted the ordinary way —
    /// the kernel calls it busy — and these mounts have no server at all.
    fn stop_serving(&self) {
        for fd in self.served.lock().unwrap().drain(..) {
            unsafe { libc::close(fd) };
        }
    }

    fn unmount(&self, mountpoint: &Path) -> Result<(), String> {
        self.stop_serving();
        self.proxy()
            .call::<_, _, ()>("Unmount", &(mountpoint.display().to_string(), false))
            .map_err(|e| error_text(&e))
    }

    /// What the daemon logged, for failure messages.
    fn journal(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }

    fn mkdir(&self, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        let _ = self.bus.kill();
        let _ = self.bus.wait();
        // Stop serving before unmounting: whatever survives the test must not
        // be able to block a process that wanders into it.
        for fd in self.served.lock().unwrap().drain(..) {
            unsafe { libc::close(fd) };
        }
        // Nothing may be left mounted under the scratch directory.
        for entry in mounted_under(&self.tmp) {
            let _ = Command::new(FUSERMOUNT)
                .args(["-u", "-z", "--"])
                .arg(&entry)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

fn error_text(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, Some(msg), _) => format!("{name}: {msg}"),
        other => other.to_string(),
    }
}

fn socketpair() -> (RawFd, RawFd) {
    let mut sv = [0 as RawFd; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(rc, 0, "socketpair failed");
    // A receive timeout keeps a broken protocol from hanging the suite.
    let tv = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            sv[0],
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    (sv[0], sv[1])
}

/// The receiving half of the `_FUSE_COMMFD` protocol.
fn recv_fd(sock: RawFd) -> Option<RawFd> {
    unsafe {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;

        if libc::recvmsg(sock, &mut msg, 0) <= 0 {
            return None;
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return None;
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg).cast::<RawFd>(), &mut fd, 1);
        Some(fd)
    }
}

/// Mountpoints under `dir`, deepest first, from the live mount table.
fn mounted_under(dir: &Path) -> Vec<PathBuf> {
    let Ok(content) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            fields.get(4).map(|f| PathBuf::from(unescape(f)))
        })
        .filter(|p| p.starts_with(dir))
        .collect();
    found.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    found
}

fn unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_mounted(path: &Path) -> bool {
    mounted_under(path).iter().any(|p| p == path)
}

// ---------------------------------------------------------------------------
// Policy refusals. These never reach fusermount3, so they need no FUSE.
// ---------------------------------------------------------------------------

#[test]
fn refuses_a_mountpoint_outside_the_allowed_root() {
    let fx = Fixture::new("outside");
    let outside = fx.tmp.join("elsewhere");
    std::fs::create_dir_all(&outside).unwrap();

    let err = fx.mount(&outside, &[]).unwrap_err();
    assert!(err.contains("outside the allowed mount roots"), "{err}");
    assert!(!is_mounted(&outside));
}

#[test]
fn refuses_the_allowed_root_itself() {
    let fx = Fixture::new("root-itself");
    let err = fx.mount(&fx.root.clone(), &[]).unwrap_err();
    assert!(err.contains("outside the allowed mount roots"), "{err}");
}

#[test]
fn refuses_a_non_empty_mountpoint() {
    let fx = Fixture::new("non-empty");
    let dir = fx.mkdir("drive");
    std::fs::write(dir.join("file"), "x").unwrap();

    let err = fx.mount(&dir, &[]).unwrap_err();
    assert!(err.contains("is not empty"), "{err}");
}

#[test]
fn refuses_a_symlink_that_leaves_the_root() {
    let fx = Fixture::new("symlink");
    let victim = fx.tmp.join("victim");
    std::fs::create_dir_all(&victim).unwrap();
    let link = fx.root.join("drive");
    std::os::unix::fs::symlink(&victim, &link).unwrap();

    let err = fx.mount(&link, &[]).unwrap_err();
    assert!(err.contains("outside the allowed mount roots"), "{err}");
    assert!(!is_mounted(&victim));
}

/// The shadowing attack in its dangerous form: the last component is a
/// genuine directory inside the root, and a *parent* component is the
/// symlink. fusermount3 alone only checks the last component.
#[test]
fn refuses_a_parent_symlink_that_leaves_the_root() {
    let fx = Fixture::new("parent-symlink");
    let victim = fx.tmp.join("victim");
    std::fs::create_dir_all(victim.join(".ssh")).unwrap();
    std::os::unix::fs::symlink(&victim, fx.root.join("a")).unwrap();

    let target = fx.root.join("a").join(".ssh");
    let err = fx.mount(&target, &[]).unwrap_err();
    assert!(err.contains("outside the allowed mount roots"), "{err}");
    assert!(!is_mounted(&victim.join(".ssh")));
}

#[test]
fn refuses_allow_other() {
    let fx = Fixture::new("allow-other");
    let dir = fx.mkdir("drive");

    let err = fx.mount(&dir, &["rw", "allow_other"]).unwrap_err();
    assert!(err.contains("allow_other"), "{err}");
    assert!(!is_mounted(&dir));
}

#[test]
fn refuses_a_caller_that_is_not_a_flatpak_app() {
    // No --allow-unsandboxed: the test process is not sandboxed.
    let fx = Fixture::with_args("unsandboxed", &[]);
    let dir = fx.mkdir("drive");

    let err = fx.mount(&dir, &[]).unwrap_err();
    assert!(err.contains("not a Flatpak application"), "{err}");
}

// ---------------------------------------------------------------------------
// Tests that make real mounts.
// ---------------------------------------------------------------------------

#[test]
fn mounts_and_unmounts_a_clean_mountpoint() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("roundtrip");
    let dir = fx.mkdir("drive");

    fx.mount(&dir, &[]).expect("a clean mountpoint must mount");
    assert!(is_mounted(&dir), "the mount must be visible to the host");

    let listed: Vec<(String, String, String, String)> = fx
        .proxy()
        .call("ListMounts", &())
        .expect("ListMounts must work");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, dir.display().to_string());

    fx.unmount(&dir).expect("its own mount must unmount");
    assert!(!is_mounted(&dir));
}

/// A mount the daemon did not create is none of its business, even for a
/// caller it would otherwise trust.
#[test]
fn refuses_to_unmount_a_mount_it_did_not_create() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("foreign");
    let dir = fx.mkdir("foreign");
    mount_directly(&dir);
    assert!(is_mounted(&dir), "the direct mount must exist");

    let err = fx.unmount(&dir).unwrap_err();
    assert!(err.contains("was not mounted through this daemon"), "{err}");
    assert!(is_mounted(&dir), "the refusal must leave it mounted");

    let _ = Command::new(FUSERMOUNT)
        .args(["-u", "-z", "--"])
        .arg(&dir)
        .status();
}

#[test]
fn enforces_the_mount_limit() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::with_args("limit", &["--allow-unsandboxed", "--max-mounts", "2"]);
    let a = fx.mkdir("a");
    let b = fx.mkdir("b");
    let c = fx.mkdir("c");

    fx.mount(&a, &[]).expect("first mount");
    fx.mount(&b, &[]).expect("second mount");
    let err = fx.mount(&c, &[]).unwrap_err();
    assert!(err.contains("limit of 2 live mounts"), "{err}");
    assert!(!is_mounted(&c));

    fx.unmount(&a).unwrap();
    fx.mount(&c, &[]).expect("a freed slot must be reusable");
    fx.unmount(&b).unwrap();
    fx.unmount(&c).unwrap();
}

/// Atomically swap two directory entries, whatever their types.
/// This is how a real attacker swaps a directory for a symlink: the path
/// is never missing, so there is no window in which the request simply
/// fails and gives the game away.
fn exchange(a: &Path, b: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    const RENAME_EXCHANGE: libc::c_uint = 1 << 1;

    let ca = CString::new(a.as_os_str().as_bytes()).unwrap();
    let cb = CString::new(b.as_os_str().as_bytes()).unwrap();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            ca.as_ptr(),
            libc::AT_FDCWD,
            cb.as_ptr(),
            RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The TOCTOU race: the caller swaps a parent component between the moment
/// the daemon approves the mountpoint and the moment the mount happens.
///
/// The attacker is deliberately well tuned — the path spends most of its
/// time as a symlink to the victim and only a short window as the genuine
/// directory, so a request that passes the check is very likely to meet
/// the symlink afterwards. Against a daemon that hands `fusermount3` a
/// *path* this succeeds and the mount lands outside the allowed root
/// (that is how the hole was found). Against one that hands it the
/// approved *descriptor*, the swap changes nothing.
#[test]
fn a_component_swap_cannot_redirect_the_mount() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("toctou");
    let victim = fx.tmp.join("victim");
    std::fs::create_dir_all(victim.join(".ssh")).unwrap();
    std::fs::write(victim.join(".ssh").join("id_ed25519"), "PRIVATE KEY").unwrap();

    // `a` is the genuine directory, `spare` the symlink to the victim;
    // exchanging them flips which one the mount path leads through.
    let parent = fx.root.join("a");
    let spare = fx.root.join("spare");
    std::fs::create_dir_all(parent.join(".ssh")).unwrap();
    std::os::unix::fs::symlink(&victim, &spare).unwrap();
    let target = parent.join(".ssh");

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let stop = Arc::clone(&stop);
        let (parent, spare) = (parent.clone(), spare.clone());
        std::thread::spawn(move || {
            let mut genuine = true;
            while !stop.load(Ordering::Relaxed) {
                if exchange(&parent, &spare).is_ok() {
                    genuine = !genuine;
                }
                // Genuine only briefly, symlink for most of the cycle.
                std::thread::sleep(if genuine {
                    Duration::from_micros(150)
                } else {
                    Duration::from_micros(1200)
                });
            }
            // Leave the genuine directory in place for cleanup.
            if !genuine {
                let _ = exchange(&parent, &spare);
            }
        })
    };

    let mut escapes = Vec::new();
    // How often the attacker actually won the race to the check — without
    // this the test would also pass against a daemon that simply refuses
    // everything, which proves nothing about the race.
    let mut past_the_check = 0;
    for _ in 0..120 {
        let outcome = fx.mount(&target, &[]);
        if outcome.is_ok()
            || !outcome
                .as_ref()
                .unwrap_err()
                .contains("outside the allowed mount roots")
        {
            past_the_check += 1;
        }
        for m in mounted_under(&fx.tmp) {
            if !m.starts_with(&fx.root) {
                escapes.push(m.clone());
                let _ = Command::new(FUSERMOUNT)
                    .args(["-u", "-z", "--"])
                    .arg(&m)
                    .status();
            }
        }
        if outcome.is_ok() {
            let _ = fx.unmount(&target);
            for m in mounted_under(&fx.root) {
                let _ = Command::new(FUSERMOUNT)
                    .args(["-u", "-z", "--"])
                    .arg(&m)
                    .status();
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
    assert!(
        escapes.is_empty(),
        "the mount escaped the allowed root onto {escapes:?}\ndaemon journal:\n{}",
        fx.journal()
    );
    assert!(
        past_the_check > 0,
        "the attacker never got past the mountpoint check, so the race was never tested"
    );
}

/// A mount made without going through the daemon, for the foreign-unmount
/// test: the same protocol, driven directly.
fn mount_directly(dir: &Path) {
    let (ours, theirs) = socketpair();
    let mut child = unsafe {
        let mut cmd = Command::new(FUSERMOUNT);
        cmd.args(["--", "."])
            .current_dir(dir)
            .env("_FUSE_COMMFD", theirs.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd.pre_exec(move || {
            if libc::fcntl(theirs, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
        cmd.spawn().expect("cannot run fusermount3")
    };
    let _ = child.wait();
    unsafe { libc::close(theirs) };
    if let Some(fd) = recv_fd(ours) {
        unsafe { libc::close(fd) };
    }
    unsafe { libc::close(ours) };
}
