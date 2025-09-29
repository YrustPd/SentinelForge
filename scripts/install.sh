#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

REPO_URL="https://github.com/YrustPd/SentinelForge"
REPO_NAME="SentinelForge"
PROJECT_ROOT=""
TEMP_PROJECT=0

log() {
  local level=$1; shift
  printf '[%s] %s\n' "$level" "$*"
}

log_info() { log INFO "$@"; }
log_warn() { log WARN "$@"; }
log_error() { log ERROR "$@" >&2; }

usage() {
  cat <<'USAGE'
SentinelForge installer
Usage: install.sh [--reinstall] [--uninstall]
  --reinstall   Reinstall SentinelForge (overwrites existing files)
  --uninstall   Remove SentinelForge binaries and data
USAGE
}

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1 && [[ -n ${BASH_SOURCE[0]:-} && -f ${BASH_SOURCE[0]} ]]; then
      exec sudo --preserve-env=DESTDIR,PREFIX bash "$0" "$@"
    fi
    log_error "SentinelForge installer must run as root. Re-run with sudo."
    exit 2
  fi
}

ensure_apt_present() {
  if ! command -v apt-get >/dev/null 2>&1; then
    log_error "This installer targets Debian/Ubuntu environments (apt-get required)."
    exit 1
  fi
}

apt_update_if_needed() {
  local lists_dir='/var/lib/apt/lists'
  local need_update=0
  if [[ ! -d $lists_dir ]] || [[ -z $(find "$lists_dir" -type f ! -name 'lock' -print -quit 2>/dev/null) ]]; then
    need_update=1
  else
    local latest
    latest=$(find "$lists_dir" -type f ! -name 'lock' -printf '%T@\n' 2>/dev/null | sort -nr | head -n1)
    local now
    now=$(date +%s)
    local age=${latest%%.*}
    if [[ -z $age ]] || (( now - age > 86400 )); then
      need_update=1
    fi
  fi
  if (( need_update == 0 )); then
    return
  fi
  log_info "Refreshing apt package metadata"
  local attempt
  for attempt in 1 2 3; do
    if DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1; then
      return
    fi
    log_warn "apt-get update failed (attempt ${attempt}); retrying in 5s"
    sleep 5
  done
  log_error "apt-get update failed after multiple attempts"
}

apt_install_packages() {
  local -a packages=()
  while [[ $# -gt 0 ]]; do
    packages+=("$1")
    shift
  done
  if ((${#packages[@]} == 0)); then
    return
  fi
  log_info "Installing packages: ${packages[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
}

ensure_packages() {
  local -a required=(
    openssh-server
    whiptail
    ufw
    fail2ban
    iproute2
    coreutils
    grep
    gawk
    sed
    procps
    curl
    ca-certificates
    make
    git
  )
  local -a missing=()
  local pkg
  for pkg in "${required[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "installed"; then
      missing+=("$pkg")
    fi
  done
  if ((${#missing[@]} > 0)); then
    apt_install_packages "${missing[@]}"
  else
    log_info "All dependencies already installed"
  fi
}

ensure_make_command() {
  if command -v make >/dev/null 2>&1; then
    return
  fi
  log_warn "'make' command missing; reinstalling package"
  apt_install_packages make
  if ! command -v make >/dev/null 2>&1; then
    log_error "Unable to locate 'make' even after reinstall; aborting"
    exit 1
  fi
}

cleanup_temp_project() {
  if (( TEMP_PROJECT == 1 )) && [[ -n ${PROJECT_ROOT:-} ]]; then
    rm -rf "$PROJECT_ROOT"
  fi
}

trap cleanup_temp_project EXIT

resolve_project_root() {
  if [[ -n ${BASH_SOURCE[0]:-} && -f ${BASH_SOURCE[0]} ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "${script_dir}/.." && pwd)"
    TEMP_PROJECT=0
    return
  fi
  if command -v git >/dev/null 2>&1; then
    PROJECT_ROOT="$(mktemp -d /tmp/sentinelforge-install.XXXXXX)"
    TEMP_PROJECT=1
    log_info "Cloning ${REPO_URL} into ${PROJECT_ROOT}"
    if ! git clone --depth 1 "${REPO_URL}" "${PROJECT_ROOT}" >/dev/null 2>&1; then
      log_error "Failed to clone ${REPO_URL}."
      exit 1
    fi
  else
    log_error "Unable to determine project root. Clone the repository and re-run install.sh."
    exit 1
  fi
}

run_make_install() {
  log_info "Installing ${REPO_NAME} into /usr/local"
  make -C "$PROJECT_ROOT" install
  if [[ ! -f /etc/sentinelforge.conf ]]; then
    install -Dm640 "$PROJECT_ROOT/etc/sentinelforge.conf" /etc/sentinelforge.conf
  fi
  mkdir -p /var/log
  touch /var/log/sentinelforge.log
  chmod 640 /var/log/sentinelforge.log
  log_info "Installation complete. Run 'sudo sentinelforge' to launch the dashboard."
}

run_uninstall() {
  if [[ -n ${BASH_SOURCE[0]:-} && -f ${BASH_SOURCE[0]} ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    "$script_dir/uninstall.sh"
  else
    local tmp
    tmp="$(mktemp -d /tmp/sentinelforge-uninstall.XXXXXX)"
    if git clone --depth 1 "${REPO_URL}" "$tmp" >/dev/null 2>&1; then
      "$tmp/scripts/uninstall.sh"
      rm -rf "$tmp"
    else
      log_error "Unable to clone repository for uninstall. Remove files manually."
      exit 1
    fi
  fi
}

MODE='install'
REINSTALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reinstall)
      REINSTALL=1
      ;;
    --uninstall)
      MODE='uninstall'
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      log_error "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ $MODE == 'uninstall' ]]; then
  need_root "$@"
  run_uninstall
  exit 0
fi

need_root "$@"
ensure_apt_present
apt_update_if_needed
ensure_packages
ensure_make_command
resolve_project_root
run_make_install
