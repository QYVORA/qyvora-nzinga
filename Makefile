# NZINGA Makefile

BINARY ?= nzinga
PREFIX ?= /usr/local
DESTDIR ?=

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
USER    ?= $(shell id -u -n)

LDFLAGS := -s -w \
	-X github.com/QYVORA/qyvora-nzinga/internal/version.Version=$(VERSION) \
	-X github.com/QYVORA/qyvora-nzinga/internal/version.Commit=$(COMMIT) \
	-X github.com/QYVORA/qyvora-nzinga/internal/version.Date=$(DATE) \
	-X github.com/QYVORA/qyvora-nzinga/internal/version.BuildUser=$(USER)

# --- install layout ------------------------------------------------------
# System-wide install (default PREFIX=/usr/local, typically needs root):
#   /usr/local/bin/nzinga                         command
#   /usr/local/share/applications/nzinga.desktop  desktop entry
#   /usr/local/share/icons/hicolor/512x512/apps/nzinga.png
#   /usr/local/share/pixmaps/nzinga.png
# User install (make install-user) mirrors the same layout under ~/.local.

ICON    := assets/nzinga.png
DESKTOP := assets/nzinga.desktop

BINDIR    := $(DESTDIR)$(PREFIX)/bin
ICONDIR   := $(DESTDIR)$(PREFIX)/share/icons/hicolor/512x512/apps
PIXMAPDIR := $(DESTDIR)$(PREFIX)/share/pixmaps
APPDIR    := $(DESTDIR)$(PREFIX)/share/applications

USERBIN    := $(HOME)/.local/bin
USERICON   := $(HOME)/.local/share/icons/hicolor/512x512/apps
USERPIXMAP := $(HOME)/.local/share/pixmaps
USERAPP    := $(HOME)/.local/share/applications

.PHONY: all build test test-race vet fmt check install install-user uninstall uninstall-user clean

all: build

build:
	go build -buildvcs=false -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/nzinga

test:
	go test ./... -count=1 -timeout 60s

test-race:
	go test -race ./... -count=1 -timeout 120s

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal pkg

check: fmt vet test

install: build
	install -d $(BINDIR)
	install -m 0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	$(MAKE) install-data

install-data:
	install -d $(ICONDIR) $(PIXMAPDIR) $(APPDIR)
	install -m 0644 $(ICON) $(ICONDIR)/nzinga.png
	install -m 0644 $(ICON) $(PIXMAPDIR)/nzinga.png
	sed -e 's|@PREFIX@|$(PREFIX)|g' $(DESKTOP) > $(APPDIR)/nzinga.desktop
	chmod 0644 $(APPDIR)/nzinga.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true
	@echo "nzinga installed to $(BINDIR) with icon and desktop entry."

install-user: build
	install -d $(USERBIN)
	install -m 0755 bin/$(BINARY) $(USERBIN)/$(BINARY)
	install -d $(USERICON) $(USERPIXMAP) $(USERAPP)
	install -m 0644 $(ICON) $(USERICON)/nzinga.png
	install -m 0644 $(ICON) $(USERPIXMAP)/nzinga.png
	sed -e 's|@PREFIX@|$(HOME)/.local|g' $(DESKTOP) > $(USERAPP)/nzinga.desktop
	chmod 0644 $(USERAPP)/nzinga.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true
	@echo "nzinga installed to $(USERBIN) with icon and desktop entry."
	@echo "Add $$HOME/.local/bin to your PATH if it is not already there."

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -f $(ICONDIR)/nzinga.png $(PIXMAPDIR)/nzinga.png $(APPDIR)/nzinga.desktop
	update-desktop-database $(APPDIR) 2>/dev/null || true
	gtk-update-icon-cache -f $(DESTDIR)$(PREFIX)/share/icons/hicolor 2>/dev/null || true

uninstall-user:
	rm -f $(USERBIN)/$(BINARY)
	rm -f $(USERICON)/nzinga.png $(USERPIXMAP)/nzinga.png $(USERAPP)/nzinga.desktop
	update-desktop-database $(USERAPP) 2>/dev/null || true
	gtk-update-icon-cache -f $(HOME)/.local/share/icons/hicolor 2>/dev/null || true

clean:
	rm -rf bin