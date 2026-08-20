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
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};
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

    /// Mount the way an application asking for `auto_unmount` does: keep the
    /// `_FUSE_COMMFD` socket open afterwards, which is how libfuse lets the
    /// helper — here, the daemon — notice the application dying. Returns the
    /// application's end of that socket, still open.
    fn mount_holding_socket(&self, mountpoint: &Path, options: &[&str]) -> Result<RawFd, String> {
        let (ours, theirs) = socketpair();
        let opts: Vec<String> = options.iter().map(|s| s.to_string()).collect();
        let result = {
            // SAFETY: `theirs` stays open until it is closed below.
            let borrowed = unsafe { BorrowedFd::borrow_raw(theirs) };
            self.proxy()
                .call::<_, _, ()>(
                    "Mount",
                    &(
                        &opts,
                        mountpoint.display().to_string(),
                        zbus::zvariant::Fd::from(borrowed),
                    ),
                )
                .map_err(|e| error_text(&e))
        };
        unsafe { libc::close(theirs) };
        let received = recv_fd(ours);
        if let Some(fd) = received {
            self.served.lock().unwrap().push(fd);
        }
        assert_eq!(
            received.is_some(),
            result.is_ok(),
            "a failed mount handed over a fuse descriptor anyway: {result:?}"
        );
        match result {
            Ok(()) => Ok(ours),
            Err(e) => {
                unsafe { libc::close(ours) };
                Err(e)
            }
        }
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

/// `auto_unmount` means what it says: the application goes away and the
/// mount goes with it, with nobody calling Unmount.
///
/// The helper cannot do this through the bridge — it would be watching the
/// daemon's socket rather than the application's — so the daemon takes the
/// option for itself and watches the application's own socket, which
/// libfuse keeps open precisely when this option was asked for.
#[test]
fn auto_unmount_removes_the_mount_when_the_application_dies() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("autounmount");
    let dir = fx.mkdir("drive");

    let app_socket = fx
        .mount_holding_socket(&dir, &["auto_unmount"])
        .expect("auto_unmount must be accepted, not refused");
    assert!(is_mounted(&dir), "the mount must be visible to the host");

    // Still there while the application lives: nothing has closed yet.
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        is_mounted(&dir),
        "the mount went away while the application was still alive\n{}",
        fx.journal()
    );

    // The application dies: it stops serving and its sockets close.
    fx.stop_serving();
    unsafe { libc::close(app_socket) };

    let deadline = Instant::now() + Duration::from_secs(10);
    while is_mounted(&dir) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !is_mounted(&dir),
        "the mount outlived the application despite auto_unmount\n{}",
        fx.journal()
    );

    // And the daemon has forgotten it, rather than leaving a record behind.
    let listed: Vec<(String, String, String, String)> = fx
        .proxy()
        .call("ListMounts", &())
        .expect("ListMounts must work");
    assert!(
        listed.is_empty(),
        "a removed mount is still listed: {listed:?}"
    );
}

/// Without the option, the same socket closing must change nothing: an
/// application that merely finished handing over is not one that has died,
/// and unmounting there would be the bridge inventing a policy of its own.
#[test]
fn without_auto_unmount_a_closed_socket_leaves_the_mount_alone() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("noauto");
    let dir = fx.mkdir("drive");

    let app_socket = fx
        .mount_holding_socket(&dir, &[])
        .expect("a clean mountpoint must mount");
    unsafe { libc::close(app_socket) };

    std::thread::sleep(Duration::from_millis(500));
    assert!(
        is_mounted(&dir),
        "the mount was removed although auto_unmount was not asked for\n{}",
        fx.journal()
    );

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

    fx.unmount(&a)
        .unwrap_or_else(|e| panic!("unmount a: {e}\ndaemon journal:\n{}", fx.journal()));
    fx.mount(&c, &[])
        .unwrap_or_else(|e| panic!("a freed slot must be reusable: {e}"));
    fx.unmount(&b).unwrap_or_else(|e| {
        panic!(
            "unmount b: {e}\nstill mounted: {}\ndaemon journal:\n{}",
            is_mounted(&b),
            fx.journal()
        )
    });
    fx.unmount(&c)
        .unwrap_or_else(|e| panic!("unmount c: {e}\ndaemon journal:\n{}", fx.journal()));
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

/// An application can stop answering on a filesystem it serves and then ask
/// for a mount inside it. Resolving that path blocks in the kernel forever,
/// so a daemon that resolved it in its only thread would never serve anyone
/// again. It must give up and carry on.
#[test]
fn an_unresponsive_filesystem_cannot_wedge_the_daemon() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("wedge");
    let hung = fx.mkdir("hung");
    let after = fx.mkdir("after");

    // The fixture holds the descriptor and answers nothing: from here on
    // any path through this mount hangs.
    fx.mount(&hung, &[]).expect("the bait must mount");
    assert!(is_mounted(&hung));

    // On a regression this call never returns at all, so it is made from a
    // thread the test can stop waiting for — a failure beats a hung suite.
    let bait = hung.join("inside");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let _ = sender.send(fx.mount(&bait, &[]));
        });
        match receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(outcome) => {
                let err = outcome.expect_err("a path into a dead filesystem must not mount");
                assert!(err.contains("not responding"), "{err}");
            }
            Err(_) => panic!("the daemon never gave up on an unresponsive filesystem"),
        }
    });

    // Still serving everyone else.
    fx.mount(&after, &[]).expect("the daemon must still work");
    assert!(is_mounted(&after));
}

/// One application waiting on a filesystem that will never answer must not
/// be able to keep another application waiting with it.
#[test]
fn a_stuck_request_does_not_hold_up_another_application() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("parallel");
    let hung = fx.mkdir("hung");
    let quick = fx.mkdir("quick");
    fx.mount(&hung, &[]).expect("the bait must mount");

    let bait = hung.join("inside");
    std::thread::scope(|scope| {
        let stuck = scope.spawn(|| fx.mount(&bait, &[]));
        // Let the first request get well into its wait before asking.
        std::thread::sleep(Duration::from_millis(300));

        let started = Instant::now();
        fx.mount(&quick, &[])
            .expect("the second application must be served");
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(3),
            "waited {waited:?} to be served while another request was stuck"
        );
        assert!(is_mounted(&quick));

        let _ = stuck.join();
    });
}

#[test]
fn several_applications_can_mount_at_once() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("concurrent");
    let dirs: Vec<PathBuf> = (0..4).map(|i| fx.mkdir(&format!("d{i}"))).collect();

    let fx = &fx;
    std::thread::scope(|scope| {
        let attempts: Vec<_> = dirs
            .iter()
            .map(|dir| scope.spawn(move || fx.mount(dir, &[])))
            .collect();
        for attempt in attempts {
            attempt
                .join()
                .expect("no thread may panic")
                .expect("every mount must succeed");
        }
    });

    for dir in &dirs {
        assert!(is_mounted(dir), "{} is not mounted", dir.display());
    }
    let listed: Vec<(String, String, String, String)> = fx
        .proxy()
        .call("ListMounts", &())
        .expect("ListMounts must work");
    assert_eq!(listed.len(), dirs.len(), "every mount must be recorded");
}

/// The mount table belongs to the whole session, and other programs mount
/// things whenever they like — including filesystems whose server has died,
/// which look exactly like a mount of ours that went astray. Removing one of
/// those means tidying up after a stranger, which is not this daemon's
/// decision to make.
///
/// This is a sanity check over the whole path, not a proof: both strangers
/// here are mounted before the request starts, so the daemon rules them out
/// early, on the mount ids it saw beforehand. The rule that matters when one
/// appears *during* a request is pinned by `policy::is_ours` and its unit
/// tests, which cover every before/after combination.
#[test]
fn a_stranger_s_filesystem_is_never_unmounted() {
    if !fuse_available() {
        eprintln!("skipping: /dev/fuse or fusermount3 is unavailable");
        return;
    }
    let fx = Fixture::new("stranger");
    // Outside the allowed root, exactly where a misplaced mount would land.
    let stranger = fx.tmp.join("stranger");
    std::fs::create_dir_all(&stranger).unwrap();

    // Two strangers: one whose server is attached, and one whose server has
    // already died — which is what a crashed FUSE filesystem leaves behind,
    // and what the daemon must resist tidying up on somebody else's behalf.
    let served = serve_directly(&stranger);
    let abandoned = fx.tmp.join("abandoned");
    std::fs::create_dir_all(&abandoned).unwrap();
    drop(serve_directly(&abandoned));
    assert!(is_mounted(&stranger));
    assert!(is_mounted(&abandoned));

    // Now make the daemon fail a mount and go looking for what it caused.
    let victim = fx.tmp.join("victim");
    std::fs::create_dir_all(victim.join(".ssh")).unwrap();
    std::os::unix::fs::symlink(&victim, fx.root.join("a")).unwrap();
    let _ = fx.mount(&fx.root.join("a").join(".ssh"), &[]);

    assert!(
        is_mounted(&stranger),
        "the daemon unmounted a filesystem somebody else was serving\ndaemon journal:\n{}",
        fx.journal()
    );
    assert!(
        is_mounted(&abandoned),
        "the daemon unmounted a stranger's abandoned filesystem; deciding when \
         somebody else's mount should go is not its job\ndaemon journal:\n{}",
        fx.journal()
    );

    drop(served);
    for path in [&stranger, &abandoned] {
        let _ = Command::new(FUSERMOUNT)
            .args(["-u", "-z", "--"])
            .arg(path)
            .status();
    }
}

/// A FUSE mount with something actually answering on it: a thread that reads
/// the requests the kernel sends and replies to none of them would hang, so
/// this replies to the handshake and then simply keeps the descriptor, which
/// is enough for the kernel to call the connection live.
fn serve_directly(dir: &Path) -> OwnedFd {
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
    let fd = recv_fd(ours).expect("the helper must hand over a descriptor");
    unsafe { libc::close(ours) };
    // SAFETY: the descriptor was just received and is not owned elsewhere.
    unsafe { OwnedFd::from_raw_fd(fd) }
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
