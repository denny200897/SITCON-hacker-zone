#!/bin/sh
# Aegis installer for macOS and Linux.
#
#   curl -fsSL https://denny.li/install.sh | sh
#
# Environment overrides:
#   AEGIS_REPO         owner/repo to download from (default denny200897/SITCON-hacker-zone)
#   AEGIS_VERSION      release tag to install (default: latest)
#   AEGIS_INSTALL_DIR  install directory (default: /usr/local/bin, else ~/.local/bin)
set -eu

REPO="${AEGIS_REPO:-denny200897/SITCON-hacker-zone}"
BINARY="aegis"

info() { printf '\033[36m==>\033[0m %s\n' "$1"; }
err()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }

os=$(uname -s)
arch=$(uname -m)
case "$os" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) err "unsupported OS: $os (on Windows use the PowerShell installer)" ;;
esac
case "$arch" in
  x86_64|amd64)  arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) err "unsupported architecture: $arch" ;;
esac

asset="aegis-${os}-${arch}"
if [ -n "${AEGIS_VERSION:-}" ]; then
  url="https://github.com/${REPO}/releases/download/${AEGIS_VERSION}/${asset}"
else
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
fi

if [ -n "${AEGIS_INSTALL_DIR:-}" ]; then
  dir="$AEGIS_INSTALL_DIR"
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
  dir="/usr/local/bin"
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT INT TERM

info "Downloading ${asset} (${os}/${arch}) …"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$url" -o "$tmp" || err "download failed: $url"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp" "$url" || err "download failed: $url"
else
  err "need curl or wget to download"
fi

# A GitHub 404 page is small HTML, not a binary; guard against that.
if [ "$(wc -c < "$tmp")" -lt 100000 ]; then
  err "downloaded file looks wrong (no release asset yet?). Check https://github.com/${REPO}/releases"
fi

chmod +x "$tmp"
target="$dir/$BINARY"
if mv "$tmp" "$target" 2>/dev/null; then
  :
else
  info "Writing $target needs elevated permissions"
  sudo mv "$tmp" "$target" || err "could not install to $dir"
fi
trap - EXIT INT TERM

info "Installed $BINARY to $target"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) info "Add it to your PATH, e.g.:  export PATH=\"$dir:\$PATH\"" ;;
esac
info "Get started:  $BINARY"
