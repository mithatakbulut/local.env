#!/bin/sh
set -eu

REPO="mithatakbulut/local.env"
SIGSTORE_ISSUER="https://token.actions.githubusercontent.com"
USER_AGENT="localenv-installer"
INSTALL_TMP=""
TMP_DIR=""

info() {
  printf '%s\n' "$*"
}

fail() {
  printf 'localenv: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "$INSTALL_TMP" ]; then
    rm -f "$INSTALL_TMP"
  fi
  if [ -n "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}

trap cleanup 0
trap 'exit 1' HUP INT TERM
umask 077

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

valid_tag() {
  printf '%s\n' "$1" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'
}

download() {
  url=$1
  destination=$2
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 10 \
    -A "$USER_AGENT" "$url" -o "$destination"
}

resolve_platform() {
  case "$(uname -s)" in
    Darwin) OS="darwin" ;;
    Linux) OS="linux" ;;
    *) fail "automatic install is supported only on macOS and Linux" ;;
  esac

  machine=$(uname -m)
  if [ "$OS" = "darwin" ] && [ "$machine" = "x86_64" ] && command -v sysctl >/dev/null 2>&1; then
    translated=$(sysctl -in sysctl.proc_translated 2>/dev/null || printf '0')
    if [ "$translated" = "1" ]; then
      machine="arm64"
    fi
  fi

  case "$machine" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) fail "automatic install is not supported on $OS/$machine" ;;
  esac
}

resolve_version() {
  if [ -n "${LOCALENV_VERSION:-}" ]; then
    TAG=$LOCALENV_VERSION
  else
    info "Resolving latest local.env release..."
    latest_url=$(curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 10 \
      -A "$USER_AGENT" -o /dev/null -w '%{url_effective}' \
      "https://github.com/$REPO/releases/latest") || fail "could not resolve the latest release"
    latest_url=${latest_url%/}
    TAG=${latest_url##*/}
  fi

  valid_tag "$TAG" || fail "invalid release tag: $TAG"
}

checksum_file() {
  path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi
  fail "sha256sum or shasum is required"
}

main() {
  need curl
  need tar
  need awk
  need grep
  need mktemp
  need cosign

  if [ -n "${LOCALENV_INSTALL_DIR:-}" ]; then
    INSTALL_DIR=$LOCALENV_INSTALL_DIR
  elif [ -n "${HOME:-}" ]; then
    INSTALL_DIR="$HOME/.local/bin"
  else
    fail "HOME is not set; set LOCALENV_INSTALL_DIR to a writable directory on PATH"
  fi

  resolve_platform
  info "Detected platform: $OS/$ARCH"
  resolve_version

  ARCHIVE="localenv_${TAG}_${OS}_${ARCH}.tar.gz"
  RELEASE_BASE="https://github.com/$REPO/releases/download/$TAG"
  IDENTITY="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$TAG"

  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/localenv-install.XXXXXX") || fail "could not create a temporary directory"
  CHECKSUMS="$TMP_DIR/checksums.txt"
  BUNDLE="$TMP_DIR/checksums.txt.bundle"
  ARCHIVE_PATH="$TMP_DIR/$ARCHIVE"

  info "Downloading localenv $TAG..."
  download "$RELEASE_BASE/checksums.txt" "$CHECKSUMS" || fail "could not download checksums.txt"
  download "$RELEASE_BASE/checksums.txt.bundle" "$BUNDLE" || fail "could not download checksums.txt.bundle"

  info "Verifying Sigstore signature..."
  cosign verify-blob \
    --bundle "$BUNDLE" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer "$SIGSTORE_ISSUER" \
    "$CHECKSUMS" >/dev/null || fail "Sigstore verification failed"

  EXPECTED=$(awk -v name="$ARCHIVE" '
    $2 == name { count++; digest=$1 }
    END {
      if (count != 1) exit 1
      print digest
    }
  ' "$CHECKSUMS") || fail "checksums.txt does not contain exactly one entry for $ARCHIVE"
  printf '%s\n' "$EXPECTED" | grep -Eq '^[0-9A-Fa-f]{64}$' || fail "invalid SHA-256 checksum for $ARCHIVE"

  download "$RELEASE_BASE/$ARCHIVE" "$ARCHIVE_PATH" || fail "could not download $ARCHIVE"

  info "Verifying SHA-256 checksum..."
  ACTUAL=$(checksum_file "$ARCHIVE_PATH")
  EXPECTED=$(printf '%s' "$EXPECTED" | tr 'A-F' 'a-f')
  ACTUAL=$(printf '%s' "$ACTUAL" | tr 'A-F' 'a-f')
  [ "$ACTUAL" = "$EXPECTED" ] || fail "release archive checksum verification failed"

  tar -xzf "$ARCHIVE_PATH" -C "$TMP_DIR" localenv || fail "could not extract localenv from $ARCHIVE"
  [ -f "$TMP_DIR/localenv" ] && [ ! -L "$TMP_DIR/localenv" ] || fail "release archive does not contain a regular localenv binary"
  chmod 0755 "$TMP_DIR/localenv"

  REPORTED_VERSION=$("$TMP_DIR/localenv" --version 2>/dev/null) || fail "downloaded localenv binary did not run"
  [ "$REPORTED_VERSION" = "$TAG" ] || fail "downloaded binary reports $REPORTED_VERSION, expected $TAG"

  mkdir -p "$INSTALL_DIR" || fail "could not create $INSTALL_DIR"
  [ -d "$INSTALL_DIR" ] || fail "$INSTALL_DIR is not a directory"
  [ -w "$INSTALL_DIR" ] || fail "$INSTALL_DIR is not writable; set LOCALENV_INSTALL_DIR to a user-writable directory"

  DESTINATION="$INSTALL_DIR/localenv"
  INSTALL_TMP=$(mktemp "$INSTALL_DIR/.localenv-install.XXXXXX") || fail "could not create a temporary file in $INSTALL_DIR"
  cat "$TMP_DIR/localenv" > "$INSTALL_TMP" || fail "could not stage localenv in $INSTALL_DIR"
  chmod 0755 "$INSTALL_TMP"
  mv -f "$INSTALL_TMP" "$DESTINATION" || fail "could not install localenv to $DESTINATION"
  INSTALL_TMP=""

  printf '\n✓ localenv %s installed to %s\n' "$TAG" "$DESTINATION"
  case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*) ;;
    *)
      printf 'Add %s to PATH before using localenv.\n' "$INSTALL_DIR"
      ;;
  esac
  printf 'Run: localenv --version\n'
}

main "$@"
