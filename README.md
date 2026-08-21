# fusebridge

FUSE mounts for sandboxed apps — without handing the app the keys to the host.

## Status

**A working prototype, not a product.** It does the whole job for real
applications and is tested against the attacks it claims to stop; it is not
packaged, released or reviewed by anyone but its author.

What works — each of these backed by a run, not by an argument:

- a full mount → I/O → unmount cycle for two **unmodified** applications:
  rclone (a Go FUSE implementation) inside a real Flatpak sandbox, and sshfs
  (libfuse 3) through the shim, with the mount visible to the whole host;
- every policy rule, exercised by the suite against a real daemon making real
  FUSE mounts — including the mountpoint-shadowing race. [SECURITY.md](SECURITY.md)
  says which test backs which claim;
- `auto_unmount`: kill the application and its mount goes with it;
- D-Bus activation from `make install`, watched starting the daemon on the
  first call;
- concurrent requests, so one application cannot make the others wait;
- builds and passes its tests on clean Debian 12, Fedora 42 and Ubuntu 24.04
  as well as the machine it was written on;
- the zero-install fallback (layer 2 below), live on KDE (kio-fuse/WebDAV)
  and GNOME (gvfs/SFTP).

What is not there yet:

- **no release and no package** — installing means building from source,
  which is fine for a developer and not fine for a user;
- **the daemon has to be on the host.** An application from a store cannot
  assume it is, which is what layer 2 exists for;
- `allow_other`/`allow_root` are refused by design, so the mount is not
  reachable by other users, by root-owned services or from containers;
- the helper's coming `--sync-init` protocol is not spoken yet (see
  *Security*), so a future libfuse could hand the shim a form it will refuse;
- x86_64 only. Nothing here is architecture-specific; nothing else has been
  run;
- the portal proposal in [docs/portal-proposal.md](docs/portal-proposal.md)
  has not been sent anywhere.

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
   localhost and the desktop's own userspace VFS (gvfs, kio-fuse) mounts
   that, under `/run/user/<uid>/`. Any program handed that path can read it;
   what varies is whether the desktop hands out the path or a `sftp://`-style
   URI only its own file layer understands. Slower than a real mount, but it
   works straight from the store with zero host-side setup.
3. **The spec** — a threat model (mountpoint shadowing, TOCTOU, foreign
   unmount) and a D-Bus interface, written up in
   [docs/portal-proposal.md](docs/portal-proposal.md) as a proposal for the
   portal issue above, with this repository as the reference implementation.
   It also carries one request to libfuse: that the pinned-mountpoint fix
   upstream already wrote should cover the code path FUSE libraries actually
   take. See *Security*.

## How the bridge works

A FUSE library with no privileges does not attach the filesystem from the
application's own process. libfuse, go-fuse and bazil/fuse — hence rclone,
borg, gocryptfs — exec `fusermount3` with the `_FUSE_COMMFD` environment
variable pointing at a unix socket, and expect the opened `/dev/fuse` fd
back over it. (Running as root, or handed a `/dev/fuse` fd some other way, a
library can mount directly. The bridge is for the unprivileged path, which
is the one a sandbox is stuck with.) That socket carries the whole of the
attach step, and fd passing is native to D-Bus. So:

- **`fusebridge-shim`** is installed inside the sandbox as
  `/app/bin/fusermount3`. It forwards the socket and the mount arguments to
  the daemon over one D-Bus name. The application is not modified at all.
  *Where* it has to go depends on the library: go-fuse and friends look
  `fusermount3` up on `PATH`, but libfuse spawns the absolute
  `FUSERMOUNT_DIR/fusermount3` it was compiled with and only falls back to
  `PATH` if that fails. An application bundling libfuse builds it with
  `--prefix=/app`, so the shim belongs at `/app/bin/fusermount3` for both
  cases — putting it on `PATH` alone is not enough.
- **`fusebridged`** runs on the host as a session daemon — no root, no
  setuid. It checks policy, then runs the host's own `fusermount3`, which
  performs the privileged step exactly as it would in a terminal and hands
  the `/dev/fuse` fd straight back to the sandboxed FUSE library through the
  forwarded socket. The filesystem daemon never leaves the sandbox.

Policy enforced by the daemon, one journal line per operation:

- the caller must be a Flatpak app running as the same user
  (`/proc/<pid>/root/.flatpak-info`); it is pinned by the pidfd the bus
  supplies, not by its pid, so a caller that hands its connection to another
  process and exits cannot be mistaken for whoever inherits the number. Its
  app id is logged;
- the mountpoint must be an empty, user-owned directory strictly inside an
  allowed root (default `~/CloudDrives`) — this is the defence against
  mounting over `~/.ssh` and similar shadowing attacks;
- `allow_other`/`allow_root` options are refused;
- a ceiling on live mounts (`--max-mounts`, 64 by default) keeps the session's
  mount table from filling up, and a ration under it
  (`--max-mounts-per-app`, 16) keeps one application from spending that
  ceiling on everyone else's behalf;
- `auto_unmount` is honoured by the daemon rather than passed on: through the
  bridge the helper would be watching the daemon's socket instead of the
  application's, so the daemon watches the application's own socket and takes
  the mount down when the application is gone;
- every request is served on its own worker, so one application waiting on a
  filesystem that never answers does not keep the others waiting;
- after the mount the daemon re-checks what actually got mounted and where;
  anything unexpected is immediately unmounted;
- unmount is possible only for mounts created through the daemon, and only by
  the app that created them — and the daemon checks *which mount* is standing
  there, not just the path, so a stranger's filesystem that took over the
  mountpoint after ours went away is left alone.

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

**Upstream found the same race, and has fixed half of it.** libfuse's
maintainer describes the identical attack in commit `bad8b22c9` (11 June
2026) — with a worse ending than the one above, a symlink into `/etc` and a
forged sudoers drop-in — and fixes it by pinning the validated directory as a
descriptor and mounting onto it with `move_mount(MOVE_MOUNT_T_EMPTY_PATH)`.
Two things keep that from settling matters here. It covers the `--sync-init`
path only; the commit says plainly that "the legacy `mount()` path and the
library direct-mount path are unchanged", and the legacy path is the one
every FUSE library takes without privilege and the only one a sandbox can
reach. And it is unreleased: 3.18.2, from March 2026, is what distributions
ship. So the machinery above stays load-bearing for as long as an unfixed
`fusermount3` is installed anywhere.

That work also brings a new way of invoking the helper —
`fusermount3 --sync-init -o <opts> -- <mountpoint>`, with a second socket in
`_FUSE_COMMFD2` and a signalling step — which the shim does not speak yet. It
refuses unknown options rather than mistaking them for a mountpoint, so the
failure is clean, but an application using it would not mount.

`cargo test` runs the attack suite in [daemon/tests/attacks.rs](daemon/tests/attacks.rs)
against a real daemon on a private bus, making real FUSE mounts: escape
outside the allowed root, the root itself, a non-empty mountpoint, a symlink
and a parent symlink leading out, `allow_other`, a non-Flatpak caller,
unmounting a mount the daemon did not create, both ceilings, a mountpoint on
a filesystem that has stopped answering, a stale record whose mountpoint a
stranger's filesystem has taken over, and the race above driven by a tuned
attacker. Every request in the suite also asserts the rule that makes
the race survivable: a refused mount never leaves the application holding a
descriptor.

The full threat model — who the adversary is, what is out of scope, which
test backs which claim, and what is still weak — is in
[SECURITY.md](SECURITY.md).

## Requirements

- Linux with FUSE and a setuid `fusermount3` at `/usr/bin/fusermount3` — the
  path is compiled in, and it is where Debian, Ubuntu, Fedora and Arch put it;
- a D-Bus session bus. dbus 1.16 or newer lets the daemon identify callers by
  descriptor; older buses work, with the caveat in [SECURITY.md](SECURITY.md);
- Rust (stable) and `make` to build. The shim additionally needs
  `rustup target add x86_64-unknown-linux-musl`, since it has to run on
  whatever runtime somebody else's Flatpak uses.

Nothing here needs root except `make install`, and the daemon itself never
runs as root.

## Install

```sh
make                 # build the daemon
make check           # fmt, clippy, and the attack suite
sudo make install    # daemon, D-Bus activation file, systemd user service
```

Nothing needs to be started: the first call from an application activates the
daemon, which then allows mounts under `~/CloudDrives` (created if missing).
`--allow-root <dir>` adds another root, `--max-mounts` and
`--max-mounts-per-app` change the ceilings,
and `--require-pidfd` refuses callers the bus cannot hand over as a
descriptor rather than identifying them by pid — worth setting if every bus
you care about is dbus 1.16 or newer. Current Debian is; Ubuntu 24.04 LTS
and Debian bookworm are not, which is why it is not the default. See
[SECURITY.md](SECURITY.md) for when that flips.

Do not add systemd sandboxing to the unit. `NoNewPrivileges=` breaks the
setuid helper — that is the very bug this project exists to route around —
and anything giving the service its own mount namespace (`PrivateTmp`,
`ProtectHome`, `ProtectSystem=strict`) hides the mounts from the rest of the
session. The shipped unit says so too.

## Using it from an application

```sh
make shim            # static, so it runs on any runtime
make install-shim    # to $(LIBDIR)/fusebridge/fusermount3, for packagers
```

In the Flatpak manifest: bundle that binary as `/app/bin/fusermount3` and add
`--talk-name=io.github.stektus.FuseBridge1` to `finish-args`. Nothing else —
no `--device=all`, and emphatically not `--talk-name=org.freedesktop.Flatpak`.
The application's own FUSE code path then works unchanged:

```sh
rclone mount remote: ~/CloudDrives/remote
```

## License

MIT.
