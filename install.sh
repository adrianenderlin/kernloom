#!/usr/bin/env sh
set -eu

# Kernloom installer
#
# Examples:
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/master/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/master/install.sh | sudo sh -s -- klshield
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/master/install.sh | sudo KERNLOOM_VERSION=v0.0.1 sh
#   curl -fsSL https://raw.githubusercontent.com/adrianenderlin/kernloom/master/install.sh | sh -s -- --prefix "$HOME/.local/bin"

REPO="adrianenderlin/kernloom"
COMPONENT="all"            # all | kliq | klshield
KERNLOOM_VERSION="${KERNLOOM_VERSION:-latest}"
PREFIX="${PREFIX:-}"
SHARE_DIR="${SHARE_DIR:-}"
TMPDIR=""

usage() {
  cat <<USAGE
Kernloom installer

Usage:
  sh install.sh [all|kliq|klshield]
  sh install.sh [--version TAG] [--prefix DIR] [--share-dir DIR] [all|kliq|klshield]

Options:
  --version TAG   Install a specific release tag (default: latest)
  --prefix DIR    Install directory for binaries
                  (default: /usr/local/bin when root, otherwise ~/.local/bin)
  --share-dir DIR Install directory for shared assets such as BPF objects
                  (default: /usr/local/share/kernloom/bpf when root,
                  otherwise ~/.local/share/kernloom/bpf)
  -h, --help      Show this help

Environment:
  KERNLOOM_VERSION   Same as --version
  PREFIX             Same as --prefix
  SHARE_DIR          Same as --share-dir
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

pick_prefixes() {
  if [ -z "$PREFIX" ]; then
    if [ "$(id -u)" -eq 0 ]; then
      PREFIX="/usr/local/bin"
    else
      PREFIX="$HOME/.local/bin"
    fi
  fi

  if [ -z "$SHARE_DIR" ]; then
    if [ "$(id -u)" -eq 0 ]; then
      SHARE_DIR="/usr/local/share/kernloom/bpf"
    else
      SHARE_DIR="$HOME/.local/share/kernloom/bpf"
    fi
  fi
}

install_file() {
  src="$1"
  dst="$2"
  mode="$3"

  if command -v install >/dev/null 2>&1; then
    install -m "$mode" "$src" "$dst"
  else
    cp "$src" "$dst"
    chmod "$mode" "$dst"
  fi
}

verify_asset() {
  asset="$1"
  file="$2"
  expected="$(awk -v a="$asset" '$2==a {print $1; exit}' "$TMPDIR/SHA256SUMS.txt")"

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

extract_release_archive() {
  remote_name="$1"
  archive="$TMPDIR/$remote_name"
  extract_dir="$TMPDIR/extract-${remote_name%.tar.gz}"

  echo "==> Downloading $remote_name" >&2
  if ! download_release_file "$remote_name" "$archive"; then
    echo "Error: failed to download $remote_name" >&2
    echo "       Check whether release '$KERNLOOM_VERSION' contains Linux/$ARCH assets." >&2
    exit 1
  fi

  verify_asset "$remote_name" "$archive"

  mkdir -p "$extract_dir"
  tar -xzf "$archive" -C "$extract_dir"
  printf '%s\n' "$extract_dir"
}

install_binary_from_dir() {
  src_dir="$1"
  bin="$2"

  found="$(find "$src_dir" -type f -name "$bin" | head -n 1 || true)"
  if [ -z "$found" ]; then
    echo "Error: could not find binary '$bin' inside extracted archive" >&2
    exit 1
  fi

  echo "==> Installing $bin to $PREFIX/$bin"
  install_file "$found" "$PREFIX/$bin" 0755
}

install_bpf_from_dir() {
  src_dir="$1"
  bpf_paths="$(find "$src_dir" -type f -name '*.bpf.o' | sort || true)"

  if [ -z "$bpf_paths" ]; then
    echo "Error: no .bpf.o file found inside klshield archive" >&2
    exit 1
  fi

  mkdir -p "$SHARE_DIR"
  first_src=""
  first_dst=""

  for src in $bpf_paths; do
    base="$(basename "$src")"
    dst="$SHARE_DIR/$base"
    echo "==> Installing $base to $dst"
    install_file "$src" "$dst" 0644
    if [ -z "$first_src" ]; then
      first_src="$src"
      first_dst="$dst"
    fi
  done

  canonical="$SHARE_DIR/xdp_kernloom_shield.bpf.o"
  if [ -n "$first_src" ] && [ "$first_dst" != "$canonical" ]; then
    echo "==> Installing canonical BPF path to $canonical"
    install_file "$first_src" "$canonical" 0644
  fi
}

install_component() {
  bin="$1"
  asset="${bin}_${KERNLOOM_VERSION}_linux_${ARCH}.tar.gz"
  extract_dir="$(extract_release_archive "$asset")"

  install_binary_from_dir "$extract_dir" "$bin"

  if [ "$bin" = "klshield" ]; then
    install_bpf_from_dir "$extract_dir"
  fi
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
    --share-dir)
      [ "$#" -ge 2 ] || { echo "Error: --share-dir requires a value" >&2; exit 1; }
      SHARE_DIR="$2"
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
need mktemp
need id
need find
need sort

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

pick_prefixes
mkdir -p "$PREFIX" "$SHARE_DIR"
TMPDIR="$(mktemp -d)"

echo "==> Kernloom release: $KERNLOOM_VERSION"
echo "==> Platform:         $OS/$ARCH"
echo "==> Binary prefix:    $PREFIX"
echo "==> BPF asset dir:    $SHARE_DIR"

echo "==> Downloading SHA256SUMS.txt"
if ! download_release_file "SHA256SUMS.txt" "$TMPDIR/SHA256SUMS.txt"; then
  echo "Error: failed to download SHA256SUMS.txt for release '$KERNLOOM_VERSION'" >&2
  exit 1
fi

case "$COMPONENT" in
  all)
    install_component klshield
    install_component kliq
    ;;
  kliq|klshield)
    install_component "$COMPONENT"
    ;;
  *)
    echo "Error: invalid component: $COMPONENT" >&2
    exit 1
    ;;
esac

echo
echo "Installed files:"
[ -x "$PREFIX/klshield" ] && echo "  - $PREFIX/klshield"
[ -x "$PREFIX/kliq" ] && echo "  - $PREFIX/kliq"
[ -f "$SHARE_DIR/xdp_kernloom_shield.bpf.o" ] && echo "  - $SHARE_DIR/xdp_kernloom_shield.bpf.o"

echo
echo "Examples:"
echo "  sudo klshield attach-xdp -iface eth0 -obj $SHARE_DIR/xdp_kernloom_shield.bpf.o"
echo "  sudo klshield stats"
echo "  sudo kliq --help"
