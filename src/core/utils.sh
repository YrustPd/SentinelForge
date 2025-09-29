#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SentinelForge_utils_timestamp() {
  date '+%Y%m%d-%H%M%S'
}

SentinelForge_utils_require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    printf '%s[!] SentinelForge requires root privileges. Re-run with sudo.%s\n' \
      "$SENTINELFORGE_COLOR_RED" "$SENTINELFORGE_COLOR_RESET" >&2
    exit 2
  fi
}

SentinelForge_utils_log() {
  local level=$1
  shift
  local message=$*
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  local dir
  dir="$(dirname "$SENTINELFORGE_LOG_FILE")"
  if [[ ! -d "$dir" ]]; then
    mkdir -p "$dir" 2>/dev/null || true
  fi
  printf '%s %-5s %s\n' "$ts" "$level" "$message" >>"$SENTINELFORGE_LOG_FILE" 2>/dev/null || true
}

SentinelForge_utils_info() { SentinelForge_utils_log INFO "$*"; }
SentinelForge_utils_warn() { SentinelForge_utils_log WARN "$*"; }
SentinelForge_utils_error() { SentinelForge_utils_log ERROR "$*"; }

SentinelForge_utils_handle_error() {
  local exit_code=$?
  local line=$1
  local command=${BASH_COMMAND:-unknown}
  SentinelForge_utils_error "Unhandled error on line ${line} (exit ${exit_code}) command: ${command}"
  printf '%sAn unexpected error occurred (line %s). Review %s for details.%s\n' \
    "$SENTINELFORGE_COLOR_RED" "$line" "$SENTINELFORGE_LOG_FILE" "$SENTINELFORGE_COLOR_RESET" >&2
  exit "$exit_code"
}

SentinelForge_utils_setup_traps() {
  trap 'SentinelForge_utils_handle_error $LINENO' ERR
  trap '' PIPE
}

SentinelForge_utils_backup_file() {
  local target=$1
  local post_restore=${2:-}
  if [[ ! -f "$target" ]]; then
    printf '%sTarget %s does not exist; skipping backup.%s\n' \
      "$SENTINELFORGE_COLOR_YELLOW" "$target" "$SENTINELFORGE_COLOR_RESET"
    return 1
  fi
  mkdir -p "$SENTINELFORGE_BACKUP_DIR"
  local timestamp
  timestamp=$(SentinelForge_utils_timestamp)
  local backup="${SENTINELFORGE_BACKUP_DIR}/$(basename "$target").${timestamp}"
  cp "$target" "$backup"
  printf '%sBackup created: %s%s\n' "$SENTINELFORGE_COLOR_GREEN" "$backup" "$SENTINELFORGE_COLOR_RESET"
  if [[ -n $post_restore ]]; then
    printf 'Restore with: cp %s %s && %s\n' "$backup" "$target" "$post_restore"
  else
    printf 'Restore with: cp %s %s\n' "$backup" "$target"
  fi
  SentinelForge_utils_info "Backup ${backup} for ${target}"
  printf '%s' "$backup"
}


SentinelForge_utils_atomic_write() {
  local path=$1
  local content=$2
  local tmp
  tmp="${path}.sf.$$"
  printf '%s' "$content" >"$tmp"
  mv "$tmp" "$path"
}

SentinelForge_utils_require_command() {
  local command_name=$1
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf '%sCommand %s is required but not installed.%s\n' \
      "$SENTINELFORGE_COLOR_RED" "$command_name" "$SENTINELFORGE_COLOR_RESET" >&2
    return 1
  fi
}

SentinelForge_utils_spinner_wait() {
  local pid=$1
  local message=${2:-Working}
  local spin='|/-\'
  local i=0
  while kill -0 "$pid" >/dev/null 2>&1; do
    printf '\r%s %s' "${spin:i++%${#spin}:1}" "$message"
    sleep 0.1
  done
  printf '\r'
}

SentinelForge_utils_path_exists() {
  local path=$1
  [[ -e "$path" ]]
}

SentinelForge_utils_tempfile() {
  mktemp "${TMPDIR:-/tmp}/sentinelforge.XXXXXX"
}
