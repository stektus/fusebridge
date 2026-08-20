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
| Make other applications wait | Every request is served on its own worker; mountpoints are claimed so two requests cannot race for one | `a_stuck_request_does_not_hold_up_another_application`, `several_applications_can_mount_at_once` |
| Impersonate another app by pid reuse, or by handing the bus connection to another process and exiting | The caller is pinned by the pidfd the bus captured together with the pid, confirmed still current after `/proc/<pid>` is opened; uid and app id are then both read through that one handle | `a_pidfd_pins_this_process`, `a_pidfd_whose_process_died_is_refused`, `dead_pid_is_an_error_not_an_identity`, and see below |
| Have the daemon unmount somebody else's filesystem | A mount is removed only if it went from connected to disconnected exactly when the daemon dropped its descriptor | `only_a_mount_that_died_with_our_descriptor_is_ours`, `a_stranger_s_filesystem_is_never_unmounted` |
| A mount outliving the application that asked for it | `auto_unmount` is honoured by the daemon itself: it watches the application's own socket and removes the mount when that closes | `auto_unmount_removes_the_mount_when_the_application_dies`, `without_auto_unmount_a_closed_socket_leaves_the_mount_alone`, `auto_unmount_is_taken_by_the_daemon_not_passed_on` |

The tests live in [daemon/tests/attacks.rs](daemon/tests/attacks.rs) and
`daemon/src/*.rs`; `cargo test` runs them against a real daemon on a private
bus, making real FUSE mounts.

## Binding a request to a caller

Every decision the daemon makes — may this caller mount at all, whose mount
is this, may this caller remove it — rests on identifying the process at the
other end of the connection. A pid is a poor handle for that. The bus reads
it once, when the connection is made, and a connection can outlive the
process that opened it: a caller may pass its bus socket to another process
over `SCM_RIGHTS` and exit, after which the bus still reports a pid that
names nobody, and then eventually names somebody else.

So the caller is pinned by descriptor. `GetConnectionCredentials` carries a
pidfd (`ProcessFD`, dbus >= 1.16) obtained at the same moment as the pid.
The daemon reads the pid *from that pidfd*, opens `/proc/<pid>`, and reads
the pidfd again. A pidfd whose process has been reaped reports `Pid: -1`
from then on, so a second reading that still names the same pid proves the
number was never released in between — and therefore that the `/proc` entry
opened between the two readings cannot have belonged to anyone else. Both
facts the policy uses, the uid and the app id, are then read through that
one pinned handle, so they cannot describe two different processes.

Verified on Linux 6.18: a live pidfd reports its pid, and the same pidfd
reports `Pid: -1` once the process is killed and reaped. That the pidfd path
is the one actually taken is not assumed either — making the fallback below
`panic!` leaves the whole attack suite passing, so every caller in it is
identified this way.

**How much this is worth, honestly.** A Flatpak application does not hold
the bus connection itself. Checked on this machine: the process the bus
reports is `xdg-dbus-proxy`, child of `bwrap`, running in the host's pid
namespace but in the *sandbox's* mount namespace — which is exactly why
`/proc/<pid>/root/.flatpak-info` describes the application. The proxy is
started by Flatpak and does not hand its connection around, so the
socket-handoff above is not a move a sandboxed application can make. What
the pinning buys against such a caller is narrower: the proxy can still exit
between the bus's reading and the daemon's, and then a bare pid could name
whatever took the number. It is the right way round either way — the
identity is read from a handle instead of assumed from a number — and it is
what upstream xdg-desktop-portal's own code has a TODO for, having read
`.flatpak-info` by bare pid ("we can use pidfd to make sure we didn't race
for sure", `shared/xdp-app-info-flatpak.c`).

This also means the app id is only as trustworthy as the sandbox's
`.flatpak-info`, which bwrap mounts read-only, and the proxy's mount
namespace, which the application cannot alter — it holds no privilege to
mount inside it, and the mounts this daemon makes land in the *host*
namespace, not the sandbox's.

On a bus too old to supply a pidfd the daemon falls back to the pid and says
so in the journal at startup. The `/proc` handle is just as stable there;
what is weaker is the claim that the pid named the caller in the first place.

**Why that degrades rather than refuses, and until when.** Refusing would be
the stricter default, and the argument for it is good: a flag is a decision,
a log line is not. Two things decide it the other way.

The first is that the exposure lands outside the threat model. Since the bus
peer is the proxy and not the application, a stale pid needs an attacker who
holds a bus connection of their own — and such a process is out of scope
here, because it can run `fusermount3` directly.

The second is who would be shut out. It is a narrower set than it first
looks, so it is worth being exact rather than saying "old distributions":

| | dbus | pidfd |
| --- | --- | --- |
| Debian 13 trixie (current stable) | 1.16.2 | yes |
| Debian 12 bookworm (oldstable) | 1.14.10 | no |
| Ubuntu 24.04 LTS noble | 1.14.10 | no |
| Ubuntu 25.10 | 1.16.2 | yes |
| Ubuntu 26.04 | 1.16.2 | yes |

Current Debian ships a bus that supplies pidfds. What carries this decision
is essentially Ubuntu 24.04 LTS alone — supported to April 2029, and
probably the largest single population of Flatpak users — with Debian
bookworm (LTS to June 2028) beside it. Refusing by default would switch the
bridge off there to close a hole those systems' sandboxed applications
cannot reach.

**So this is a concession with an expiry, not a permanent design.** When
bookworm and noble are out of support — mid-2028 and April 2029 — nothing
still in service ships dbus 1.14, and the default should flip: refuse by
default, with a flag for the fallback rather than for the strictness. That
decision is made here, conditionally, so it does not have to be argued
again; what remains is to notice the date.

Until then the strictness is available as a deliberate act:
**`--require-pidfd`** refuses any caller the bus cannot hand over as a
descriptor. It changes nothing on a bus that supplies them, which is pinned
by `require_pidfd_changes_nothing_on_a_bus_that_supplies_them`.

The refusal itself is not left to argument either. On a real dbus 1.14.10
(Debian 12 in a container, its own session bus, no `ProcessFD` among the
credentials it offers), the same daemon answering the same request differs
only by the flag:

- with `--require-pidfd`: `AccessDenied: this bus cannot identify callers by
  descriptor (needs dbus >= 1.16) and --require-pidfd is set`, and at startup
  `every request will be refused`;
- without it: `'/nowhere' is outside the allowed mount roots` — the caller
  was identified, and the request went on to be judged on policy.

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

Recognising which mount to remove is the delicate part, because the mount
table belongs to the whole session and other programs mount and crash
whenever they like. Two facts narrow the field — the mount did not exist
when the operation started, and its FUSE connection appeared while the
helper ran — and one decides: while the daemon holds the descriptor its own
mount is connected, and letting go disconnects that mount and nothing else
in the session. So the mount that *changed* is the daemon's.

Both narrowing facts are weaker than they look, and getting them wrong is
how a stray mount stays. Neither the mount id nor the connection number is a
lasting name: the kernel hands both back and gives them out again, so a
comparison across time is by id *and* place, never by number alone. And the
narrowing by connection is only available when the kernel is publishing its
connection list at all — `/sys/fs/fuse/connections` is an ordinary empty
directory when `fusectl` is not mounted, which reads exactly like "no
connections are new". Treating that as an answer switched the cleanup off
entirely; treated as "unavailable", the decision falls back on the liveness
transition, which is the part that carries the argument anyway. Finally, the
question "did anything land astray?" is not answered by one instantaneous
reading of the mount table, because the helper may still be attaching it —
so the daemon keeps looking for a bounded while before concluding that
nothing did.

All three were found by running the attack suite on clean systems rather
than only on the machine it was written on. A filesystem somebody is serving answers throughout; one that was
already disconnected belongs to some other program whose server died on its
own, and deciding when that should be cleaned up is not this daemon's
business. Both are left alone.

That last distinction was not there at first, and its absence was a bug: a
crashed filesystem elsewhere in the session, appearing during a request,
matched everything the daemon then looked at.

Note where that argument is needed and where it is not. Reasoning about
which mount in the session is the daemon's only arises on the revert path,
because that is where the daemon removes something — and there it is
airtight, since the daemon is the one letting go of the descriptor and can
argue from cause. A mount that *succeeded* needs no such reasoning: it is
recorded under the directory that was approved and verified, which is the
same key an unmount request is matched against.

What is best-effort is forgetting: `sweep_stale` drops records whose mounts
have gone, and it decides that from `/proc/self/mountinfo`, which can come
back inconsistent. The worst it can do is drop a record too early, and the
cost of that is an unmount the daemon afterwards declines to perform. It
never causes a removal. The strong rule guards the half that can.

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
- **It has been built and tested on more than the machine it was written
  on.** Clean installs of Debian 12, Fedora 42 and Ubuntu 24.04 in
  containers: builds from source with no undeclared dependency, `make
  install` places all three files, and the suite runs with real mounts and
  nothing skipped. That is where the mount-recognition bugs above came from
  — two of those systems supply no pidfd (dbus 1.14), all three publish no
  connection list, and the fuse versions ranged over 3.14.0, 3.16.2 and
  3.18.2.
- **`fusermount3` accepts only options it knows, and drops the dangerous
  ones.** An invented option is refused outright (`unknown option
  'totally_made_up_option'`), and asking for `suid` or `dev` is answered with
  `unsafe option ... ignored` — the resulting mount is `nosuid,nodev`
  regardless of what was requested. Checked by driving the helper directly
  on fuse 3.18.2 and, identically, on fuse 3.14.0. This bounds what "options
  are passed through" can mean,
  but it is the helper's rule, not this daemon's, so the daemon does not lean
  on it: the options it forbids, it refuses itself, including padded
  spellings the helper happens to reject today.

## Known limits

- **A misplaced mount exists briefly**, as described above — dead from the
  moment it exists, then removed. "Briefly" is the daemon noticing it and
  succeeding: it now looks for up to two seconds rather than once, because
  looking once lost the race often enough to leave the mount there for good.
  If the removal itself fails, the daemon says so in the journal
  (`could not remove misplaced mounts`) rather than passing over it.
- **`auto_unmount` rests on what libfuse does with its socket.** The daemon
  removes the mount when the application's `_FUSE_COMMFD` socket reaches
  end-of-file, which is a sound signal only because libfuse keeps that
  socket open exactly when `auto_unmount` was requested and closes it
  immediately otherwise (`fuse_mount_fusermount`). A library that kept the
  socket open without asking for the option would get no cleanup; one that
  closed it early while asking for it would have its mount taken down under
  it. Neither is libfuse's behaviour, and the option is never acted on
  unless it was asked for — but this is somebody else's convention, not a
  guarantee this daemon can make.
- **Forgetting a mount is possible in principle.** The kernel builds
  `/proc/self/mountinfo` as it is read, so a reading taken while the session
  is mounting and unmounting can come back without an entry that was there
  throughout. A record is only dropped after two readings agree it is gone,
  and never because the read failed — but two readings are not a proof.
- **Mount options other than the refused ones are passed through** to
  `fusermount3` as the application gave them. The daemon does not attempt to
  understand them; it relies on nothing about them either (see above).
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
