# fusebridge

FUSE mounts for sandboxed apps — without handing the app the keys to the host.

## Status

**Design stage. Nothing here works yet.** This README describes what is being
built and why; the moment code lands, this line changes.

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

## License

MIT.
