# fusebridge

FUSE mounts for sandboxed apps — without handing the app the keys to the host.

## Status

**Working prototype, hardened against the attacks it claims to stop.** The
bridge (daemon + shim) performs a full mount → I/O → unmount cycle for an
unmodified rclone running inside a Flatpak sandbox, with the mount visible to
the whole host. Every policy rule is exercised by the test suite against a
real daemon making real mounts, including the mountpoint-shadowing race
described below. The zero-install fallback (layer 2) is verified live on KDE
(kio-fuse/WebDAV) and GNOME (gvfs/SFTP). Not yet done: D-Bus activation and
packaging, a second and third application beyond rclone, and the written
spec for the portal issue.

## The problem

A Flatpak app cannot mount a FUSE filesystem. `fusermount3` is setuid-root and
`NoNewPrivs=1` inside the sandbox strips that, so `mount(2)` is refused. The
only workaround in use today is `--talk-name=org.freedesktop.Flatpak` plus
`flatpak-spawn --host` — a permission that lets the app run *any* command on
the host. Apps that need mounts (backup tools, encrypted volumes, cloud
drives) either take that hole or ship without mounting.

A portal to fix this properly was proposed in January 2022
([xdg-desktop-portal#695](https://github.com/flatpak/xdg-desktop-portal/issues/695))
and has not received a single comment since.

## The design

The privileged step — attaching a filesystem to the host's mount tree — cannot
be taken away from the host; anything else would be a kernel bug. What can be
built is a narrow, auditable contract for requesting it. Three layers:

1. **The bridge** — a small session daemon on the host. A sandboxed app talks
   to one D-Bus name and passes the `_FUSE_COMMFD` socket that its FUSE
   library already uses; the daemon enforces policy (which app, which
   mountpoint, journal) and runs the host's own `fusermount3`. The filesystem
   daemon stays inside the sandbox; only the attach happens outside.
2. **The fallback** — no helper installed? The app serves WebDAV/SFTP on
   localhost and the desktop's own userspace VFS (gvfs, kio-fuse) makes it
   visible to every program. Slower, but works straight from the store with
   zero host-side setup.
3. **The spec** — a threat model (mountpoint shadowing, TOCTOU, foreign
   unmount) and a D-Bus interface written up as a draft for the portal issue
   above, with this repository as the reference implementation.

## How the bridge works

FUSE libraries (libfuse, go-fuse, bazil/fuse — hence rclone, borg, gocryptfs)
do not call `mount(2)` themselves: they exec `fusermount3` with the
`_FUSE_COMMFD` environment variable pointing at a unix socket and expect the
opened `/dev/fuse` fd back over it. That socket is the entire contract, and
fd passing is native to D-Bus. So:

- **`fusebridge-shim`** is installed inside the sandbox as
  `/app/bin/fusermount3`. It forwards the socket and the mount arguments to
  the daemon over one D-Bus name. The application is not modified at all.
- **`fusebridged`** runs on the host as a session daemon — no root, no
  setuid. It checks policy, then runs the host's own `fusermount3`, which
  performs the privileged step exactly as it would in a terminal and hands
  the `/dev/fuse` fd straight back to the sandboxed FUSE library through the
  forwarded socket. The filesystem daemon never leaves the sandbox.

Policy enforced by the daemon, one journal line per operation:

- the caller must be a Flatpak app (`/proc/<pid>/root/.flatpak-info`, same
  uid); its app id is logged;
- the mountpoint must be an empty, user-owned directory strictly inside an
  allowed root (default `~/CloudDrives`) — this is the defence against
  mounting over `~/.ssh` and similar shadowing attacks;
- `allow_other`/`allow_root` options are refused;
- a ceiling on live mounts (`--max-mounts`, 64 by default) keeps one app from
  filling the session's mount table;
- after the mount the daemon re-checks what actually got mounted and where;
  anything unexpected is immediately unmounted;
- unmount is possible only for mounts created through the daemon, and only
  by the app that created them.

## Security

**Checking the path is not enough, so the daemon does not stop there.**
`fusermount3` resolves the mountpoint again when it runs, and it only rejects
a symlink in the *final* component. A caller that swaps a *parent* component
for a symlink after the check — atomically, with
`renameat2(RENAME_EXCHANGE)`, so the path is never missing — redirects the
mount anywhere it likes. Verified against fuse 3.18.2: the mount landed on a
directory outside the allowed root, one attempt in six.

The daemon therefore resolves the path exactly once and keeps the resulting
directory open, so the check describes an inode rather than a name. It then
mounts on that descriptor (`fchdir` into it, `.` as the mountpoint) — which
narrows the window but does not close it, because `fusermount3` turns any
argument back into a path (`fuse_mnt_resolve_path`) and resolves it again
before mounting. Nothing the daemon can pass avoids that.

**So the daemon takes the `/dev/fuse` descriptor itself.** `fusermount3`
reports to the daemon, not to the application: the descriptor is handed on
only once the mount is confirmed to sit on the approved directory. Otherwise
it is closed, which aborts the connection — a mount that landed somewhere
else is dead on arrival, serves nothing to anybody, and is then removed. The
attack turns from "shadow `~/.ssh` with a filesystem you control" into "make
a directory answer ENOTCONN for a moment".

Identifying that stray mount is done by three facts together, because the
mount table belongs to the whole session: it did not exist when the operation
started, its FUSE connection appeared while the helper ran (connection
numbers are reused after an abort, so that alone proves nothing), and it died
exactly when the daemon dropped the descriptor. A filesystem somebody else
mounted at that moment is left alone.

`cargo test` runs the attack suite in [daemon/tests/attacks.rs](daemon/tests/attacks.rs)
against a real daemon on a private bus, making real FUSE mounts: escape
outside the allowed root, the root itself, a non-empty mountpoint, a symlink
and a parent symlink leading out, `allow_other`, a non-Flatpak caller,
unmounting a mount the daemon did not create, the mount ceiling, and the race
above driven by a tuned attacker. Every request in the suite also asserts the
rule that makes the race survivable: a refused mount never leaves the
application holding a descriptor. The race test additionally asserts that the
attacker *did* get past the mountpoint check, so it cannot pass by accident.

Known and deliberate limits:

- **App ids identify sandboxed callers, nothing else.** A process that can
  create a user namespace can chroot into a forged root and claim any app id;
  verified by doing it, and by taking over another app's mount that way. It
  gains nothing — such a process is unsandboxed and can run `fusermount3`
  directly — and the callers this policy governs cannot do it: Flatpak's
  seccomp filter refuses `unshare(CLONE_NEWUSER)` inside the sandbox, with
  and without `--devel` (checked on flatpak 1.18.1).
- **The daemon is single-threaded.** A mount request can hold it for up to
  15 seconds, and a hung filesystem on the path to a mountpoint can block it
  for longer. Not a hole, but a denial of service one app can inflict on
  another; it wants a worker per request before this is fit to ship.
- **A redirected mount still exists for a moment.** It is dead and unserved
  from the instant it appears, and removed before the request returns, but
  the window is real. Closing it properly needs `fusermount3` to accept a
  directory descriptor instead of a path — which is one of the concrete
  proposals this project takes to the portal issue.

## Try it

```sh
cargo build --release                                            # daemon
cargo build --release -p fusebridge-shim \
    --target x86_64-unknown-linux-musl                           # static shim

# Host side:
./target/release/fusebridged            # allows mounts under ~/CloudDrives

# Application manifest (Flatpak):
#   * bundle the shim as /app/bin/fusermount3
#   * finish-args: --talk-name=io.github.stektus.FuseBridge1
# The app's normal FUSE code path then just works:
rclone mount remote: ~/CloudDrives/remote
```

## License

MIT.
