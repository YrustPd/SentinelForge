#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SentinelForge_updates_refresh_state() {
  local force=${1:-}
  local now
  now=$(date +%s)
  local ttl=${SENTINELFORGE_UPDATES_LOCAL_TTL:-300}
  local last=${SENTINELFORGE_STATE[pending_updates_checked_epoch]:-0}
  if [[ $force == force || $last -eq 0 || $(( now - last )) -ge $ttl ]]; then
    local pending
    pending=$(SentinelForge_detect_pending_updates || printf '0')
    SENTINELFORGE_STATE[pending_updates]="${pending}"
    SENTINELFORGE_STATE[unattended_enabled]=$(SentinelForge_detect_unattended_enabled)
    SENTINELFORGE_STATE[pending_updates_checked_epoch]=$now
  fi
  SENTINELFORGE_STATE[version_local]="${SENTINELFORGE_VERSION}"
  SentinelForge_updates_check_remote_version "$force"
}

SentinelForge_updates_enable_unattended() {
  SentinelForge_utils_require_root
  if [[ ${SENTINELFORGE_STATE[unattended_enabled]:-no} == "yes" ]]; then
    SentinelForge_ui_show_message 'Updates' 'Unattended upgrades already enabled.'
    return 0
  fi
  local manager
  manager=$(SentinelForge_detect_package_manager)
  case "$manager" in
    apt-get|apt)
      if ! SentinelForge_ui_prompt_confirm "Enable unattended-upgrades?" false; then
        return 0
      fi
      DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
      if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unattended-upgrades >/dev/null 2>&1; then
        systemctl enable unattended-upgrades >/dev/null 2>&1 || true
        systemctl start unattended-upgrades >/dev/null 2>&1 || true
        SentinelForge_ui_show_message 'Updates' 'Unattended upgrades enabled.'
      else
        SentinelForge_ui_show_message 'Updates' 'Failed to enable unattended upgrades.'
      fi
      ;;
    dnf|yum)
      SentinelForge_ui_show_message 'Updates' 'Enable automatic updates via dnf-automatic on this platform.'
      ;;
    zypper)
      SentinelForge_ui_show_message 'Updates' 'Configure automatic updates with zypper services manually.'
      ;;
    pacman)
      SentinelForge_ui_show_message 'Updates' 'Automatic updates must be configured manually on pacman-based systems.'
      ;;
    *)
      SentinelForge_ui_show_message 'Updates' 'Package manager not recognized. Configure unattended updates manually.'
      ;;
  esac
  SentinelForge_updates_refresh_state
}

SentinelForge_updates_check_remote_version() {
  local force=${1:-}
  local now
  now=$(date +%s)
  local last_epoch=${SENTINELFORGE_STATE[version_checked_epoch]:-0}
  local ttl=${SENTINELFORGE_UPDATES_CACHE_TTL:-3600}
  if [[ $force != force && $last_epoch -gt 0 && $(( now - last_epoch )) -lt $ttl ]]; then
    return 0
  fi
  local remote='unreachable'
  local status='unknown'
  local url=${SENTINELFORGE_VERSION_URL:-'https://raw.githubusercontent.com/YrustPd/SentinelForge/main/VERSION'}
  if command -v curl >/dev/null 2>&1; then
    local fetched
    fetched=$(curl --silent --show-error --fail --location --connect-timeout 3 --max-time 8 "$url" 2>/dev/null | tr -d '\r' | head -n1 || true)
    if [[ -n $fetched ]]; then
      remote=$fetched
    fi
  elif command -v wget >/dev/null 2>&1; then
    local fetched
    fetched=$(wget -q -O - "$url" 2>/dev/null | tr -d '\r' | head -n1 || true)
    if [[ -n $fetched ]]; then
      remote=$fetched
    fi
  fi
  if [[ $remote == "${SENTINELFORGE_VERSION}" ]]; then
    status='up-to-date'
  elif [[ $remote == 'unreachable' ]]; then
    status='unknown'
  else
    status='update-available'
  fi
  SENTINELFORGE_STATE[version_remote]="$remote"
  SENTINELFORGE_STATE[version_status]="$status"
  SENTINELFORGE_STATE[version_checked]=$(date '+%Y-%m-%d %H:%M:%S')
  SENTINELFORGE_STATE[version_checked_epoch]=$now
  if [[ $status != 'update-available' ]]; then
    unset SENTINELFORGE_STATE[version_notified]
  fi
}

SentinelForge_updates_perform_self_update() {
  SentinelForge_utils_require_root
  local url=${SENTINELFORGE_INSTALL_URL:-'https://raw.githubusercontent.com/YrustPd/SentinelForge/main/scripts/install.sh'}
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'Updates' 'curl or wget is required to download updates.'
    return 1
  fi
  if ! SentinelForge_ui_prompt_confirm "Reinstall SentinelForge from the latest upstream script?" false; then
    return 0
  fi
  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/sentinelforge-update.XXXXXX")
  if command -v curl >/dev/null 2>&1; then
    if ! curl --silent --show-error --fail --location --connect-timeout 3 --max-time 30 "$url" -o "$tmp"; then
      rm -f "$tmp"
      SentinelForge_ui_show_message 'Updates' 'Failed to download update script.'
      return 1
    fi
  else
    if ! wget -q -O "$tmp" "$url"; then
      rm -f "$tmp"
      SentinelForge_ui_show_message 'Updates' 'Failed to download update script.'
      return 1
    fi
  fi
  if bash "$tmp"; then
    SentinelForge_ui_show_message 'Updates' 'SentinelForge updated successfully.'
    SentinelForge_updates_check_remote_version force
  else
    SentinelForge_ui_show_message 'Updates' 'Failed to update SentinelForge from upstream.'
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}
