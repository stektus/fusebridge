# fusebridge

FUSE mounts for sandboxed apps — without handing the app the keys to the host.

## Status

**Working prototype.** The bridge (daemon + shim) performs a full
mount → I/O → unmount cycle for an unmodified rclone running inside a Flatpak
sandbox, with the mount visible to the whole host; policy denials (mountpoint
outside the allowed roots, `allow_other`, non-Flatpak callers, missing D-Bus
permission) are verified live. The zero-install fallback (layer 2 below) is
verified live on KDE (kio-fuse/WebDAV) and GNOME (gvfs/SFTP). Not yet done:
hardening tests against deliberate attacks (shadowing, TOCTOU races), D-Bus
activation packaging, and the written spec.

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
- after the mount the daemon re-checks what actually got mounted and where;
  anything unexpected is immediately unmounted;
- unmount is possible only for mounts created through the daemon, and only
  by the same app id.

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
