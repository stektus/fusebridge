PREFIX      ?= /usr
BINDIR      ?= $(PREFIX)/bin
LIBDIR      ?= $(PREFIX)/lib
DATADIR     ?= $(PREFIX)/share
DESTDIR     ?=
CARGO       ?= cargo
SHIM_TARGET ?= x86_64-unknown-linux-musl

DAEMON  := target/release/fusebridged
SHIM    := target/$(SHIM_TARGET)/release/fusebridge-shim

.PHONY: all daemon shim check install install-shim uninstall clean

all: daemon

daemon:
	$(CARGO) build --release -p fusebridge-daemon

# The shim runs inside somebody else's Flatpak, on whatever runtime that app
# uses, so it is built static: one binary, no dependency on the runtime's C
# library. Needs `rustup target add $(SHIM_TARGET)`.
shim:
	$(CARGO) build --release -p fusebridge-shim --target $(SHIM_TARGET)

check:
	$(CARGO) fmt -- --check
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) test

# Installs the host side: the daemon, its D-Bus activation file and a user
# service. Application authors take the shim separately, see install-shim.
install: daemon
	install -Dm755 $(DAEMON) $(DESTDIR)$(BINDIR)/fusebridged
	install -d $(DESTDIR)$(DATADIR)/dbus-1/services $(DESTDIR)$(LIBDIR)/systemd/user
	sed 's|@BINDIR@|$(BINDIR)|g' packaging/io.github.stektus.FuseBridge1.service.in \
		> $(DESTDIR)$(DATADIR)/dbus-1/services/io.github.stektus.FuseBridge1.service
	sed 's|@BINDIR@|$(BINDIR)|g' packaging/fusebridge.service.in \
		> $(DESTDIR)$(LIBDIR)/systemd/user/fusebridge.service

# The static shim, for whoever is building an application that will use the
# bridge: bundle it into the Flatpak as /app/bin/fusermount3.
install-shim: shim
	install -Dm755 $(SHIM) $(DESTDIR)$(LIBDIR)/fusebridge/fusermount3

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/fusebridged
	rm -f $(DESTDIR)$(DATADIR)/dbus-1/services/io.github.stektus.FuseBridge1.service
	rm -f $(DESTDIR)$(LIBDIR)/systemd/user/fusebridge.service
	rm -f $(DESTDIR)$(LIBDIR)/fusebridge/fusermount3
	-rmdir $(DESTDIR)$(LIBDIR)/fusebridge 2>/dev/null

clean:
	$(CARGO) clean
