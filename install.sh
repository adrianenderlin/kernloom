#!/usr/bin/env sh
set -eu

# Kernloom installer
#
# Examples:
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/main/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/main/install.sh | sudo sh -s -- klshield
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/main/install.sh | sudo KERNLOOM_VERSION=v0.0.1 sh
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/main/install.sh | sh -s -- --prefix "$HOME/.local/bin"

REPO="adrianenderlin/kernloom"
COMPONENT="all"            # all | kliq | klshield
KERNLOOM_VERSION="${KERNLOOM_VERSION:-latest}"
PREFIX="${PREFIX:-}"
TMPDIR=""

usage() {
  cat <<USAGE
Kernloom installer

Usage:
  sh install.sh [all|kliq|klshield]
  sh install.sh [--version TAG] [--prefix DIR] [all|kliq|klshield]

Options:
  --version TAG   Install a specific release tag (default: latest)
  --prefix DIR    Install directory (default: /usr/local/bin when root,
                  otherwise ~/.local/bin)
  -h, --help      Show this help

Environment:
  KERNLOOM_VERSION   Same as --version
  PREFIX             Same as --prefix
USAGE
}

cleanup() {
  if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT INT TERM

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: missing required command: $1" >&2
    exit 1
  }
}

resolve_latest_version() {
  # Follow GitHub redirect and extract the final tag from the Location header.
  location="$({
    curl -fsSI "https://github.com/$REPO/releases/latest" || exit 1
  } | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | tail -n 1)"

  tag="${location##*/}"
  if [ -z "$tag" ] || [ "$tag" = "latest" ]; then
    echo "Error: could not resolve latest Kernloom release" >&2
    exit 1
  fi
  printf '%s\n' "$tag"
}

pick_prefix() {
  if [ -n "$PREFIX" ]; then
    return 0
  fi

  if [ "$(id -u)" -eq 0 ]; then
    PREFIX="/usr/local/bin"
  else
    PREFIX="$HOME/.local/bin"
  fi
}

install_file() {
  src="$1"
  dst="$2"

  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$src" "$dst"
  else
    cp "$src" "$dst"
    chmod 0755 "$dst"
  fi
}

verify_asset() {
  asset="$1"
  file="$2"
  expected="$(grep "  $asset$" "$TMPDIR/SHA256SUMS.txt" | awk '{print $1}' || true)"

  if [ -z "$expected" ]; then
    echo "Error: checksum for $asset not found in SHA256SUMS.txt" >&2
    exit 1
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    actual="$(openssl dgst -sha256 "$file" | awk '{print $NF}')"
  else
    echo "Warning: no SHA-256 tool found; skipping checksum verification" >&2
    return 0
  fi

  if [ "$actual" != "$expected" ]; then
    echo "Error: checksum mismatch for $asset" >&2
    exit 1
  fi
}

download_release_file() {
  remote_name="$1"
  out="$2"
  url="https://github.com/$REPO/releases/download/$KERNLOOM_VERSION/$remote_name"

  curl -fL --retry 3 --connect-timeout 10 -o "$out" "$url"
}

install_binary() {
  bin="$1"
  asset="${bin}_${KERNLOOM_VERSION}_linux_${ARCH}.tar.gz"
  archive="$TMPDIR/$asset"
  extract_dir="$TMPDIR/extract-$bin"

  echo "==> Downloading $asset"
  if ! download_release_file "$asset" "$archive"; then
    echo "Error: failed to download $asset" >&2
    echo "       Check whether release '$KERNLOOM_VERSION' contains Linux/$ARCH assets." >&2
    exit 1
  fi

  verify_asset "$asset" "$archive"

  mkdir -p "$extract_dir"
  tar -xzf "$archive" -C "$extract_dir"

  found="$(find "$extract_dir" -type f -name "$bin" | head -n 1 || true)"
  if [ -z "$found" ]; then
    echo "Error: could not find binary '$bin' inside $asset" >&2
    exit 1
  fi

  echo "==> Installing $bin to $PREFIX/$bin"
  install_file "$found" "$PREFIX/$bin"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    all|kliq|klshield)
      COMPONENT="$1"
      shift
      ;;
    --version)
      [ "$#" -ge 2 ] || { echo "Error: --version requires a value" >&2; exit 1; }
      KERNLOOM_VERSION="$2"
      shift 2
      ;;
    --prefix)
      [ "$#" -ge 2 ] || { echo "Error: --prefix requires a value" >&2; exit 1; }
      PREFIX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown argument: $1" >&2
      echo >&2
      usage >&2
      exit 1
      ;;
  esac
done

need curl
need tar
need uname
need awk
need grep
need mktemp
need id

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"

case "$OS" in
  linux) ;;
  *)
    echo "Error: Kernloom releases currently target Linux only (detected: $OS)" >&2
    exit 1
    ;;
esac

case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Error: unsupported architecture: $ARCH_RAW" >&2
    exit 1
    ;;
esac

if [ "$KERNLOOM_VERSION" = "latest" ]; then
  KERNLOOM_VERSION="$(resolve_latest_version)"
fi

pick_prefix
mkdir -p "$PREFIX"
TMPDIR="$(mktemp -d)"

echo "==> Kernloom release: $KERNLOOM_VERSION"
echo "==> Platform: $OS/$ARCH"
echo "==> Prefix:   $PREFIX"

# SHA256SUMS is expected for release verification.
echo "==> Downloading SHA256SUMS.txt"
if ! download_release_file "SHA256SUMS.txt" "$TMPDIR/SHA256SUMS.txt"; then
  echo "Error: failed to download SHA256SUMS.txt for release '$KERNLOOM_VERSION'" >&2
  exit 1
fi

case "$COMPONENT" in
  all)
    install_binary klshield
    install_binary kliq
    ;;
  kliq|klshield)
    install_binary "$COMPONENT"
    ;;
  *)
    echo "Error: invalid component: $COMPONENT" >&2
    exit 1
    ;;
esac

echo
echo "Installed binaries:"
[ -x "$PREFIX/klshield" ] && echo "  - $PREFIX/klshield"
[ -x "$PREFIX/kliq" ] && echo "  - $PREFIX/kliq"

echo
echo "Notes:"
echo "  - Current releases install the CLI binaries only."
echo "  - If you attach klshield to XDP, you still need the matching BPF object"
echo "    unless you later embed or ship it as an additional release asset."

echo
echo "Examples:"
echo "  sudo klshield --help"
echo "  sudo kliq --help"