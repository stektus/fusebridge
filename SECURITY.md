# Threat model

This is a security-relevant component: it lets a sandboxed application ask
for something it is not allowed to do itself. What follows is what it
promises, what it does not, and what backs each claim. Every enforced rule
names the test that exercises it; every claim that rests on a one-off
experiment says so.

Nothing here is a substitute for review. If you find a hole, please open an
issue — the design is meant to be argued with.

## What is being protected, and from whom

The bridge exists so that an application confined by Flatpak can attach a
filesystem to the host's mount tree. That is a privileged act, and the point
of the exercise is to grant it *narrowly* — narrowly enough that granting it
is better than the alternative in use today, which is
`--talk-name=org.freedesktop.Flatpak` plus `flatpak-spawn --host`, i.e. the
ability to run any command on the host.

**The adversary is the application itself.** It is assumed to be hostile,
to have been written specifically against this daemon, and to be able to
retry as often as it likes. It reaches the daemon through one D-Bus name and
nothing else.

**Assets:**

- the user's files, in particular the ability to *shadow* a directory —
  mounting over `~/.ssh` so the next `ssh` reads keys the attacker supplies
  is the motivating example, and it needs no read access to the victim;
- the integrity of the session's mount table;
- the user's ability to keep using their machine (denial of service);
- the sandbox boundary itself: nothing the bridge does may become a way to
  run code outside the sandbox.

**Explicitly out of scope:**

- an unsandboxed process on the same session bus. It can run `fusermount3`
  itself; the bridge gives it nothing new. The daemon still refuses to serve
  it unless started with `--allow-unsandboxed`, which exists for testing.
- root on the machine, other users, and anything that can already write to
  the user's home outside the mount roots.
- the *contents* served over a mount. A filesystem an application serves is
  as trustworthy as the application; the bridge attaches it, it does not
  vouch for it. This is why mountpoints are confined to a dedicated root and
  why `allow_other` is refused.

## Trust boundaries

```
  sandboxed app ── libfuse/go-fuse ── shim (in the sandbox, /app/bin/fusermount3)
                                        │
                                        │  D-Bus: one name, one method,
                                        │  the _FUSE_COMMFD socket as a
                                        │  file descriptor
                                        ▼
                    fusebridged (host, session bus, no root, no setuid)
                                        │
                                        │  fork/exec, descriptor in hand
                                        ▼
                    /usr/bin/fusermount3 (setuid, the host's own)
```

The daemon holds no privilege of its own. The privileged step is performed
by the same setuid helper the user could run in a terminal, with the same
authority, and the daemon's whole contribution is deciding *whether* and
*where*. The filesystem daemon never leaves the sandbox: only the attach
happens outside, and the `/dev/fuse` descriptor is passed back in.

## Threats and what answers them

| Threat | What answers it | Evidence |
| --- | --- | --- |
| Any local process asks for a mount | Caller must be a Flatpak app: same uid, `.flatpak-info` read through a pinned `/proc/<pid>` handle | `refuses_a_caller_that_is_not_a_flatpak_app` |
| Mount over a sensitive directory (`~/.ssh`) | Mountpoint must be an empty, user-owned directory strictly inside an allowed root | `refuses_a_mountpoint_outside_the_allowed_root`, `refuses_the_allowed_root_itself`, `refuses_a_non_empty_mountpoint` |
| Escape the root through a symlink | The path is resolved once and the *resulting directory* is checked, not the name | `refuses_a_symlink_that_leaves_the_root`, `refuses_a_parent_symlink_that_leaves_the_root` |
| Escape by swapping a path component *during* the mount (TOCTOU) | The descriptor is withheld until the mount is confirmed; a misplaced mount is dead on arrival and removed | `a_component_swap_cannot_redirect_the_mount`, and see below |
| Expose the mount to other users of the machine | `allow_other`/`allow_root` refused, including smuggled inside another option | `refuses_allow_other`, `rejects_option_smuggling` |
| Unmount another application's filesystem | Only mounts this daemon made, and only for the app that made them | `refuses_to_unmount_a_mount_it_did_not_create`, `unmount_is_restricted_to_the_owning_app`, plus a live cross-app run (see below) |
| Fill the session's mount table | A ceiling on live mounts (`--max-mounts`, 64 by default) | `enforces_the_mount_limit` |
| Freeze the daemon for everyone | Mountpoint resolution runs on its own thread with a deadline; abandoned checks are counted and capped | `an_unresponsive_filesystem_cannot_wedge_the_daemon` |
| Impersonate another app by pid reuse | `/proc/<pid>` is opened once and everything is read through that handle | `dead_pid_is_an_error_not_an_identity` |

The tests live in [daemon/tests/attacks.rs](daemon/tests/attacks.rs) and
`daemon/src/*.rs`; `cargo test` runs them against a real daemon on a private
bus, making real FUSE mounts.

## The one that needed more than a check

`fusermount3` resolves the mountpoint path *again* when it runs
(`fuse_mnt_resolve_path`, then `lstat`, then `chdir`), and it only refuses a
symlink in the final component. An application that swaps a *parent*
component for a symlink in that instant — atomically, with
`renameat2(RENAME_EXCHANGE)`, so the path is never missing — redirects the
mount out of the allowed root. Measured against fuse 3.18.2: **20 successful
escapes in 120 attempts** against a daemon that checked the path first.
Pinning the directory and passing `fchdir` + `.` narrows the window; it does
not close it (4 in 120). No argument the daemon can pass avoids the second
resolution.

What closes it is refusing to make the result useful. `fusermount3` reports
to the daemon, not to the application: the daemon receives the `/dev/fuse`
descriptor, confirms the mount is on the approved directory, and only then
passes it on. Otherwise it closes the descriptor, which aborts the
connection — the misplaced mount is dead from the moment it exists, serves
nothing to anyone, and is then removed. The attack degrades from "shadow
`~/.ssh` with a filesystem you control" to "make a directory answer ENOTCONN
for a moment".

Recognising which mount to remove takes three facts together, because the
mount table belongs to the whole session: it did not exist when the
operation started, its FUSE connection appeared while the helper ran
(connection numbers are reused after an abort, so the number alone proves
nothing), and it died exactly when the daemon dropped the descriptor.
Anything else is somebody else's filesystem and is left alone.

Residual risk: the misplaced mount exists, dead, for the few milliseconds
between the mount and its removal. Closing that properly needs
`fusermount3` to accept a directory descriptor instead of a path — a change
upstream, and one of the concrete proposals this project carries to
[xdg-desktop-portal#695](https://github.com/flatpak/xdg-desktop-portal/issues/695).

## Claims resting on experiments rather than tests

- **App ids identify sandboxed callers and nothing else.** A process that
  can create a user namespace can chroot into a forged root and claim any
  app id. Verified by doing it, including taking over another
  application's mount. It gains nothing: such a process is unsandboxed and
  can run `fusermount3` directly. What matters is that the callers this
  policy governs cannot do it — Flatpak's seccomp filter refuses
  `unshare(CLONE_NEWUSER)` inside the sandbox, with and without `--devel`
  (checked on flatpak 1.18.1).
- **Cross-application unmount is refused in practice**, not only in the unit
  test: a mount made by an app running as `org.freedesktop.Platform` was not
  removable by a caller with a different identity on the same bus; the
  daemon logged the refusal and the mount survived.
- **The bridge works for more than one FUSE library.** Verified with rclone
  (a Go implementation) inside a Flatpak sandbox, and with sshfs (libfuse 3,
  C) through the shim: mount, read, write, unmount.

## Known limits

- **The daemon serves one request at a time.** Resolution has a deadline, so
  it can no longer be wedged for good, but a mount request can still hold it
  for around twenty seconds in the worst case. That is a denial of service
  one application can inflict on another. A worker per request is the fix
  and has not been done.
- **A misplaced mount exists briefly**, as described above.
- **`auto_unmount` is implemented but not exercised** by any test or live
  run.
- **Mount options other than the refused ones are passed through** to
  `fusermount3` as the application gave them. The daemon does not attempt to
  understand them.
- **The mount root is only as safe as the application's other permissions.**
  If an application also holds broad filesystem access (`--filesystem=home`
  or `host`), it can rearrange the mount root directly, and the bridge is
  not what stands between it and the user's files. The bridge is designed
  for applications that hold *no* filesystem permission on the mount root —
  which they do not need, since it is other programs that read the mount.

## Reporting

Open an issue at https://github.com/stektus/fusebridge/issues. There is no
release process yet and no users to coordinate with, so there is nothing to
embargo: a public issue with a reproducer is the fastest path to a fix.
