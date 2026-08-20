# A FUSE mount portal: threat model, interface, and a working implementation

*A proposal for [xdg-desktop-portal#695](https://github.com/flatpak/xdg-desktop-portal/issues/695).
Reference implementation: this repository, MIT.*

This issue asked for a FUSE portal in January 2022 and has had no discussion
since. I built a working implementation to find out whether the idea survives
contact with the details. It does — but only because of one design decision
that is not obvious until you try to attack it, and it took three bugs found on
other people's distributions to get the cleanup right. This is the problem, an
interface proposal, the threat model, and the things I got wrong on the way,
offered as a starting point rather than as a finished design.

Measurements were taken on Manjaro with fuse 3.18.2, flatpak 1.18.1,
dbus 1.16.2, Linux 6.18, and re-run on clean Debian 12, Fedora 42 and
Ubuntu 24.04. Where a claim rests on a single experiment rather than on a test
in the suite, it says so.

## 1. The problem

A Flatpak application cannot mount a FUSE filesystem, and both routes out are
closed:

- `fusermount3` is setuid-root, and the sandbox sets `NoNewPrivs=1`, so the
  setuid bit is ignored on `execve` and `mount(2)` is refused.
- Mounting unprivileged in a user namespace of its own does not work either:
  Flatpak's seccomp filter refuses `unshare(CLONE_NEWUSER)`, with and without
  `--devel` (checked on flatpak 1.18.1).

The workaround in use today is `--talk-name=org.freedesktop.Flatpak` together
with `flatpak-spawn --host`, which is the permission to run *any* command on
the host. An application that wants to expose a cloud drive ends up holding a
permission that makes its sandbox decorative — and the Spawn portal cannot be
narrowed, which is acknowledged in
[flatpak#5161](https://github.com/flatpak/flatpak/issues/5161). Applications in
this position — backup tools, encrypted volumes, cloud storage clients — today
choose between shipping without mounts and shipping without a meaningful
sandbox.

## 2. Why this can be a portal at all

The privileged step — attaching a filesystem to the host's mount tree — cannot
be handed to the sandbox. That is not a bug to fix; it is the boundary working.

What makes a portal possible is that the unprivileged FUSE handoff is already
tiny and already descriptor-based. A FUSE library with no privileges does not
attach the filesystem from the application's own process: libfuse, go-fuse and
bazil/fuse all exec `fusermount3` with `_FUSE_COMMFD` pointing at a unix
socket, and expect the opened `/dev/fuse` descriptor back over it
(`SCM_RIGHTS`, with a single zero byte of ordinary data).

So the portal needs no kernel work, and — this is the part that surprised me —
no application changes either. The application keeps its existing FUSE code
path; something in the sandbox has to answer to the name `fusermount3`, and
that something forwards the request over D-Bus. The filesystem daemon never
leaves the sandbox. Only the attach happens outside.

### 2.1 Why not `fsopen`/`fsmount`/`move_mount`?

Because a portal is an ordinary unprivileged session process, and the new
mount API needs `CAP_SYS_ADMIN` in the caller's mount namespace exactly as
`mount(2)` does. Measured on Linux 6.18 as the session user:

```
fsopen("fuse")  = -1  Operation not permitted
fsopen("tmpfs") = -1  Operation not permitted
mount(2) tmpfs  = -1  Operation not permitted
```

A process can give itself that capability by creating its own user and mount
namespace, and then the whole chain works: inside `unshare -Urm`,
`fsopen` → `fsconfig` → `fsmount` → `move_mount` all succeed. But the mount
then exists only in that namespace. With a tmpfs mounted on a directory
there, a file written into it is visible from inside while the same path
reads as an empty directory from the session, and the host's mount table has
no entry for it at all. A mount other programs can see is the one thing this
feature has to deliver, so the namespace route is not a route.

That leaves the setuid helper as the only carrier of the privilege, which is
why this proposal is shaped around `fusermount3` rather than around the
syscalls — and why section 8 asks libfuse for a change rather than asking the
kernel for one.

## 3. Shape: this belongs with the Documents portal, not the UI portals

The Request/Response pattern used by the UI portals fits interactions that show
the user a dialog. This one has no dialog in the common case, passes
descriptors, and is called from inside a library's mount path where the caller
is blocked waiting. The closest existing sibling is
`org.freedesktop.portal.Documents`: a plain D-Bus service with direct returns
and fd passing. I would model it on that.

A sibling, though, and not an extension. The document portal runs a FUSE
filesystem of its own to export *host* files *into* sandboxes, under its own
control. This one attaches a filesystem the *sandbox* serves and exports it
*out* to the host — the opposite direction, and the opposite trust flow: there
the portal is the server and the sandbox the client, here the sandbox is the
server and every program on the host a potential client. The overlap worth
having is in the machinery, not the filesystem: app identification, the
fd-passing contract, the activation model.

## 4. Proposed interface

```
interface org.freedesktop.portal.Fuse {

    /* Attach a FUSE filesystem at `mountpoint`. `comm_fd` is the caller's
       own end of the socketpair its FUSE library made: the portal writes
       the /dev/fuse descriptor into it, exactly as fusermount3 would, and
       keeps its copy for as long as the mount lives. */
    Mount(in  s      mountpoint,     /* absolute path */
          in  as     options,        /* fusermount3 mount options */
          in  h      comm_fd,
          in  a{sv}  options_extra);

    Unmount(in s mountpoint,
            in b lazy);

    /* Mounts this caller currently owns: mountpoint, fstype, source. */
    ListMounts(out a(sss) mounts);

    readonly property u version;
}
```

**Taking the caller's socket rather than returning the descriptor over the
bus.** The obvious alternative is `Mount(... out h fuse_fd)`, with the
sandbox-side shim writing the descriptor into its own socket. It is a
cleaner-looking signature and I proposed it first. The reason to prefer the
one above is in section 7, in one line: the socket is simultaneously the
transport and an exact liveness signal, and libfuse's own semantics make it
exact. The alternative signature has no signal at all — the shim exits
milliseconds after a successful mount, so its bus connection is gone while
the mount is young, and there is nothing whose lifetime matches the mount to
watch. Anything the `out h` version does to recover that ends up being a
descriptor the caller passes in, which is this signature with an extra step.

What is not negotiable either way: **the portal receives the `/dev/fuse`
descriptor from `fusermount3` first**, and releases it only after checking
the mount. That is section 6.

**`options_extra` follows the portal convention: unknown keys are ignored,
not refused**, and a client that needs to know whether a key is understood
checks the `version` property first. Refusing them would be the stricter
reading, and for a security-relevant interface that is tempting — an option
the caller believed was applied and silently was not is a real hazard. The
convention wins anyway, because refusing breaks forward compatibility in the
worse direction: a new client would fail outright against an old portal
instead of degrading. The rule that keeps it safe is that anything
security-relevant goes in behind a `version` bump, so a client can tell
before it relies on it.

**`mountpoint` is a path, not a descriptor**, because the caller has no
descriptor to give that would mean anything on the host side. This is the
weakest part of the interface, and section 8 is the one change upstream that
would fix it.

## 5. Policy the portal has to enforce

Each of these exists because something goes wrong without it.

**5.1 Identify the caller by descriptor, not by pid.** A pid from the bus says
who connected, not who is alive now. Take the pidfd the bus supplies
(`ProcessFD` in `GetConnectionCredentials`, dbus ≥ 1.16), read the pid from it,
open `/proc/<pid>`, then read the pidfd again: a reaped process reports
`Pid: -1` from then on, so an unchanged second reading proves the number was
never released, and the `/proc` entry opened in between cannot have been anyone
else's. Read the uid and the app id through that one handle so they cannot
describe two different processes.

Three honest qualifications:

- For a Flatpak caller the bus peer is not the application but its
  `xdg-dbus-proxy` — in the host's pid namespace, in the sandbox's mount
  namespace, which is exactly why `root/.flatpak-info` read through it
  describes the application. So this is not a defence against an application
  handing its connection away; it cannot do that. It closes the ordinary case
  of the peer exiting mid-request.
- `ProcessFD` is not everywhere yet. Debian 13 and Ubuntu 25.10 ship
  dbus 1.16.2; Debian 12 and Ubuntu 24.04 LTS still ship 1.14.10, which offers
  only `ProcessID` and `UnixUserID` (checked in containers). A portal needs a
  stated policy for old buses. Mine degrades to pid with a warning by default
  and has `--require-pidfd` to refuse instead — the reasoning being that with
  `xdg-dbus-proxy` as the peer, exploiting a stale pid requires an adversary
  with its own bus connection, who is unsandboxed and can run `fusermount3`
  directly. Both behaviours are verified against a real dbus 1.14.10.
- This is not a bug report against xdg-desktop-portal.
  `xdp_app_info_flatpak_new` already takes a pidfd and reaches the bwrap
  instance through the instance id, though it opens `.flatpak-info` by bare pid
  and carries the comment *"TODO: we can use pidfd to make sure we didn't race
  for sure"*. A FUSE portal built on that machinery inherits whatever that TODO
  resolves to, which is an argument for resolving it.

And one property of the app id that a specification should state rather than
imply: **it identifies sandboxed callers and nobody else.** A process that can
create a user namespace can chroot into a forged root and present any
`.flatpak-info` it likes — I verified this by doing it, including taking over
another app's mount. It gains nothing, because a process that unprivileged
can already run `fusermount3` itself; the policy governs applications that
cannot, and inside a Flatpak sandbox the forgery is unavailable because the
seccomp filter refuses `unshare(CLONE_NEWUSER)`. But the app id is an
attribution, not an authentication, and it should be documented as one.

**5.2 Confine the mountpoint.** Mounting over `~/.ssh` so that the next `ssh`
reads keys the attacker supplies is the motivating attack, and it needs no read
access to the victim. The mountpoint must be an empty, user-owned directory
strictly inside a root the portal controls — the root itself refused, symlinks
leading out refused, resolved once and then held open so the check describes an
inode rather than a name.

**5.3 Refuse `allow_other` and `allow_root`,** including padded and
`key=value` spellings. `fusermount3` rejects some of those itself — it has a
whitelist and forces `nosuid,nodev` — but a portal should not depend on the
spellings somebody else's parser happens to tolerate.

**5.4 Cap the number of live mounts per application, under a session
ceiling.** Mount table entries are a finite shared resource, so the session
needs a ceiling — but a ceiling alone is a denial-of-service instrument in
the hands of the first application to reach it. Everything else here is
decided per application; the ration should be too. My implementation now
does both (16 per application under a session ceiling of 64), with requests
in flight counted against the ration, since otherwise a burst of concurrent
requests walks past it.

**5.5 Restrict unmount** to mounts the portal made, and to the app that made
them — and check *which mount*, not just which path.

A record is keyed by a path, and the path outlives the mount that sat on it.
If the portal's mount is removed by other means and another program mounts
there, acting on the record removes a stranger's filesystem — the very thing
the portal refuses to do for a path it has no record of at all. The same
applies to `auto_unmount`: the death of an application says nothing about a
filesystem it never owned.

The kernel makes this easy to get wrong. Measured on 6.18: unmount a FUSE
filesystem and mount another at the same path, and **both the mount id and
the FUSE connection number come back identical** — three times out of three,
on the very next attempt. Nothing in `/proc/self/mountinfo` distinguishes the
two mounts. What does is `STATX_MNT_ID_UNIQUE` (Linux 6.8), documented as
never reused and observed to differ on each of those mounts; it also answers
for a mount whose server has died, where `ls` fails with `ENOTCONN`, which
matters because removing dead mounts is most of what unmounting is for. On
older kernels — Debian 12 runs 6.1 — there is no exact answer available, and
the check degrades to the recycled id, which catches a replacement only when
the number happens to differ.

**5.6 Serve requests concurrently.** A mountpoint on a filesystem that has
stopped answering blocks the request that touches it — `lstat` on a hung FUSE
mount does not return. If that runs on the connection thread, one application
hangs the portal for everybody. One worker per request; verified by a test that
was first confirmed to fail (4.77 s of waiting) with the work moved back onto
the connection thread.

## 6. The race that shapes the whole design

This is the part I would most like reviewed, because checking the mountpoint
before calling the helper is the obvious design and it does not work.

`fusermount3` resolves the mountpoint path *again* when it runs
(`fuse_mnt_resolve_path`, then `lstat`, then `chdir`), and it only refuses a
symlink in the *final* component. A caller that swaps a *parent* component for
a symlink in that instant — atomically, with `renameat2(RENAME_EXCHANGE)`, so
the path is never missing — redirects the mount out of the allowed root.

Measured against fuse 3.18.2 with a tuned attacker: **20 successful escapes in
120 attempts** against a service that checked the path first. Pinning the
directory with an open descriptor and passing `fchdir` + `.` narrows the window
but does not close it — **4 in 120** — because the helper turns any argument
back into a path and resolves it again. No argument the caller can pass avoids
the second resolution.

What closes it is refusing to make the result useful. **`fusermount3` reports
to the portal, not to the application.** The portal receives the `/dev/fuse`
descriptor, confirms the mount landed on the approved directory, and only then
passes it on. Otherwise it closes it, which aborts the connection: a mount that
landed somewhere else is dead from the moment it exists, serves nothing to
anybody, and is then removed. The attack degrades from "shadow `~/.ssh` with a
filesystem you control" to "make a directory answer `ENOTCONN` for a few
milliseconds".

### 6.1 Removing the stray mount is harder than it looks

The mount table belongs to the whole session, and other programs mount and
crash whenever they like. Removing the wrong entry would be a worse bug than
the one being fixed. Two facts narrow the field — the mount did not exist when
the operation started, and its FUSE connection appeared while the helper ran
(connection numbers are reused after an abort, so the number alone proves
nothing) — and one decides it: while the portal holds the descriptor its own
mount is connected, and letting go disconnects that mount and nothing else in
the session. So the mount that *changed* is the portal's. A filesystem somebody
is still serving answers throughout; one that was already disconnected belongs
to another program whose server died on its own, and cleaning that up is not
the portal's business.

That last distinction was missing in my first version, and its absence was a
bug: a crashed filesystem elsewhere in the session, appearing during a request,
matched everything the service then looked at — including, on this machine, a
crashed `xdg-document-portal` mount.

### 6.2 Three more bugs that only appeared on other people's systems

All three were invisible on the development machine and were found by running
the suite on clean Debian 12, Fedora 42 and Ubuntu 24.04. Anyone implementing
the revert path above will meet them.

1. **`/sys/fs/fuse/connections` is an empty directory unless `fusectl` is
   mounted, and none of the three distributions mounts it by default.** Reading
   it as "there are no FUSE connections" rather than "I cannot observe
   connections" silently disabled the check that finds the stray mount.
   Measured: 2 failures in 3 runs.
2. **Mount ids are reused by the kernel**, promptly. A fresh mount that
   inherited a retired id looks pre-existing if you compare by id alone.
   Compare id *and* mountpoint. With only bug 1 fixed: 3 failures in 10 runs.
   And that pairing is only enough for "did this appear during my operation":
   for "is this still the same mount" it is not enough at all, because at one
   path the id comes straight back — see 5.5.
3. **One instantaneous reading of `/proc/self/mountinfo` decides nothing** —
   `fusermount3` may not have finished attaching. Watch for a short window
   (2 s) instead of looking once.

With all three fixed: 0 failures in 15 runs, then 8 of 8 clean runs on Debian
and on Ubuntu.

## 7. `auto_unmount`, and why it decides the signature in section 4

`auto_unmount` asks the helper to take the mount down when the application
dies. Through a portal the helper is on the wrong side of the boundary: it
would be watching the portal's socket, not the application's, so it would never
fire. Passing the option through therefore produces a mount that claims a
guarantee it does not have.

What makes the feature implementable is a detail of libfuse worth stating
explicitly, because the whole thing rests on it. In `fuse_mount_fusermount`
(mount.c, checked in 3.18.2):

```c
int fd = receive_fd(fds[1]);
if (!mo->auto_unmount) {
    /* with auto_unmount option fusermount3 will not exit until
       this socket is closed */
    close(fds[1]);
    waitpid(pid, NULL, 0); /* bury zombie */
}
```

libfuse holds its own end of the `_FUSE_COMMFD` socketpair open **exactly when
`auto_unmount` was requested**, and closes it immediately otherwise. So
end-of-file on the other end means the application is gone, and means nothing
else.

My implementation therefore strips the option from the helper's arguments —
otherwise the helper sits watching the wrong socket forever — keeps the
application's socket end, polls it, and unmounts on EOF. Verified live with a
purpose-written libfuse3 filesystem and `kill -9`: the mount went away, and
`Unmount` was never called. Negative control: with the watcher disabled the
test fails with "the mount outlived the application despite auto_unmount".

**This is what decides the signature in section 4.** A portal that returns the
descriptor over the bus and never touches the application's socket has no such
signal, and the substitutes are worse:

- *Watch the caller's bus connection.* The caller is the shim, and the shim
  exits within milliseconds of a successful mount — that is what `fusermount3`
  does, and the reason libfuse `waitpid()`s for it. Its connection is therefore
  gone while the mount is new and perfectly healthy, so this signal fires on
  every mount, immediately, and means nothing.
- *Watch the sandbox instance instead.* This one is real: verified by killing
  a running instance, `flatpak kill` and `kill -9` on the process inside the
  sandbox both take the instance's `xdg-dbus-proxy` down with it, within about
  four seconds. But it is coarser than the mount it is standing in for — an
  application with several processes in one sandbox keeps its instance, and
  its bus connections, after the process serving the filesystem has died.
- *Take a descriptor from the caller purely as a liveness token.* This works,
  and it is the section 4 signature with an extra argument: the token that
  would do the job exactly is the socket.

Leaving it to the sandbox side does not work either: real `fusermount3` with
`auto_unmount` survives as an orphan and unmounts on EOF, and a shim could do
the same, but when the whole sandbox is torn down the shim dies with it and
nobody unmounts. The watcher has to be outside, and the thing worth watching
is the socket.

## 8. One concrete request upstream, to libfuse

**`fusermount3` should be able to mount on a directory descriptor it is given,
without resolving a path.**

Everything in section 6 is a workaround for the second resolution. With a
`fusermount3` that accepts an already-open directory fd — inherited across
`exec`, named by number, say `fusermount3 --mountpoint-fd=N` — the check and
the mount would describe the same inode, the race would not exist, and a
portal would need neither the descriptor-withholding machinery nor the revert
path. The interface could then be honest about it and take a directory
descriptor from the caller as well.

Concretely, `fuse_mnt_resolve_path` and the `chdir` after it are what would
be skipped; the attach itself can address the descriptor directly with
`move_mount(mfd, "", dirfd, "", MOVE_MOUNT_F_EMPTY_PATH)` on a kernel new
enough for the new mount API, and `fchdir(dirfd)` followed by mounting on
`"."` — never re-deriving a path from the argument — on one that is not. The
setuid check that matters (`is this directory the caller's to mount on`) is
the same either way, and reads the descriptor rather than a name.

This is a small change in a well-defined place, and the portal work does not
depend on it: the design above works without it, at the cost of a short-lived
dead mount and a good deal of complexity that exists only to detect one.

## 9. What the reference implementation demonstrates

A session daemon and a static shim: about 2300 lines of Rust and 1700 of
tests. It is a prototype, not a product — no releases yet, and the bus name
sits in a personal namespace precisely because it should move if this idea
goes anywhere.

- **Unmodified applications.** Full mount → read → write → unmount for rclone
  (a Go FUSE implementation) inside a real Flatpak sandbox, and for sshfs
  (libfuse 3, C) through the shim. Neither was changed. The manifest gains
  `--talk-name=<the bus name>` and nothing else: no `--device=all` — the host's
  `fusermount3` opens `/dev/fuse` — and emphatically not
  `--talk-name=org.freedesktop.Flatpak`.
- **65 tests**, of which 21 are integration tests against a real daemon on a
  private bus, making real FUSE mounts: escapes outside the root, the root
  itself, non-empty mountpoints, symlinks in the last and in a parent
  component, `allow_other`, a non-Flatpak caller, unmounting somebody else's
  mount, both ceilings, a mountpoint on a filesystem that has stopped
  answering, concurrent callers, `auto_unmount` on a killed application, a
  stale record whose path has been taken over by a stranger's mount, and the
  race in section 6 driven by a tuned attacker. Every request in the suite
  also asserts the rule that makes the race survivable: a refused mount never
  leaves the application holding a descriptor.
- **Negative controls**, because a green test proves nothing until it has been
  seen to fail: the race test was first run against the vulnerable version to
  confirm it catches it; the concurrency test was confirmed to fail with the
  work moved back onto the connection thread; the pidfd path was confirmed to
  be the one actually taken by making the fallback `panic!` and watching the
  suite still pass; the mount-identity check of 5.5 was disabled, and the
  daemon then unmounted the stranger's filesystem, which is the bug the check
  exists for.
- **Clean-environment runs.** Build, `fmt`, `clippy`, `make install` and the
  full suite on Debian 12, Fedora 42 and Ubuntu 24.04 in containers, with
  nothing skipped. This is where section 6.2 came from.

Two packaging details that cost me an afternoon each, and that any portal
documentation will need to state:

- **libfuse execs the absolute `FUSERMOUNT_DIR/fusermount3` it was compiled
  with**, and only falls back to `PATH` if that fails; go-fuse and friends use
  `PATH`. An application bundling libfuse builds it with `--prefix=/app`, so
  the shim has to be at `/app/bin/fusermount3`. Putting it on `PATH` alone
  silently does nothing — my first sshfs test proved nothing for exactly this
  reason.
- **libfuse 3.18.2 invokes the helper in four forms**, and a shim that handles
  only the obvious one breaks in a way nobody sees:

  | form | when |
  |---|---|
  | `--version` | probing |
  | `-o <opts> -- <mp>` | mounting |
  | `--unmount --quiet --lazy -- <mp>` | unmounting, **after the app's own `umount2()` fails** — i.e. exactly in a sandbox |
  | `--auto-unmount -- <mp>` | watchdog, after a direct `mount(2)` succeeded |

  The unmount form uses long options that do not appear in `fusermount3
  --help`. A shim that does not parse them takes `--unmount` for a mountpoint,
  and the request goes out as a *mount*. Observed before the fix: the
  filesystem exits, the mount stays behind dead, and nothing reaches the
  daemon at all, because libfuse does not wait for the helper on this path.

## 10. Open questions I would rather have answered than decide alone

- **Where do mounts live?** My implementation uses a configured root
  (`~/CloudDrives` by default) and requires the directory to exist, be empty,
  and be owned by the user. A portal could instead own the root and create a
  per-app directory itself, the way the document portal does, which removes the
  emptiness dance and most of 5.2. The trade-off is discoverability: users want
  their cloud drive at a path they chose, not under `$XDG_RUNTIME_DIR`. I lean
  towards portal-owned directories with an opt-in symlink or a user-chosen
  root, but that is a desktop-integration question more than a security one.
- **Should the first mount by an application prompt the user?** Policy is
  static now, which is what makes the design cheap. A prompt would make it a UI
  portal, with the Request/Response machinery that implies.
- **What happens to mounts when the portal restarts?** Mine keeps its records
  in memory and loses the ability to unmount across a restart. A real
  implementation probably wants them to survive, which means state on disk and
  a way to re-adopt mounts — and, given 5.5, a mount identity that survives a
  restart too.

## 11. Known limits of the design as it stands

- The misplaced mount from section 6 exists, dead, for a few milliseconds.
  Section 8 is how that goes away.
- Records can be dropped early: the kernel builds `/proc/self/mountinfo` as it
  is read, so a reading taken while the session is busy can come back without
  an entry that was there throughout. Dropping only after two readings agree
  makes this rare, not impossible. The failure mode is a refusal to unmount
  later, never an unwanted removal.
- The mount-identity check of 5.5 is exact only on Linux 6.8 and newer. Below
  that the kernel offers no identifier that is not recycled, so a mount that
  replaced ours at the same path, quickly enough to inherit its number, is
  indistinguishable from ours. The window is narrow and the consequence is
  bounded — a FUSE mount of the user's own, inside the portal's own root,
  removed when it should not have been — but it is not zero.
- The mount root is only as safe as the calling application's other
  permissions. An app that also holds `--filesystem=home` can rearrange the
  root directly, and this portal is not what stands between it and the user's
  files. The design is for applications that hold no filesystem permission on
  the mount root at all — which they do not need, since it is other programs
  that read the mount.

---

I am not attached to any of the above except section 6, which I think is
forced. If the interface should look different, or this belongs somewhere other
than xdg-desktop-portal, I would rather hear that now than build more on it.
