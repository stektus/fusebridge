//! Constants shared between the host daemon and the sandbox shim.

/// Well-known bus name the daemon claims on the session bus.
pub const BUS_NAME: &str = "io.github.stektus.FuseBridge1";

/// Object path the bridge interface is served at.
pub const OBJECT_PATH: &str = "/io/github/stektus/FuseBridge1";

/// Interface name (same as the bus name, versioned).
pub const INTERFACE: &str = "io.github.stektus.FuseBridge1";

/// Environment variable libfuse-compatible libraries use to hand
/// `fusermount3` the unix socket over which the /dev/fuse fd is returned.
pub const COMMFD_ENV: &str = "_FUSE_COMMFD";
