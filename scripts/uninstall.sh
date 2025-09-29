#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SENTINELFORGE_DDOS_CHAIN='SF_DDOS_GUARD'
SENTINELFORGE_DDOS_LOG_CHAIN='SF_DDOS_LOG'
SENTINELFORGE_DDOS_IPSET='sentinelforge_ddos_block'
SENTINELFORGE_DDOS_TABLE='sentinelforge_ddos'
SENTINELFORGE_DDOS_SYSCTL_PROFILE='/etc/sysctl.d/99-sentinelforge-ddos.conf'
SENTINELFORGE_SYSCTL_PROFILE='/etc/sysctl.d/99-sentinelforge.conf'
SENTINELFORGE_CONFIG_FILE='/etc/sentinelforge.conf'
SENTINELFORGE_NGINX_DIR='/etc/nginx/sentinelforge'
SENTINELFORGE_LOG_FILE='/var/log/sentinelforge.log'
SENTINELFORGE_BACKUP_DIR=${SENTINELFORGE_BACKUP_DIR:-/etc/sentinelforge/backups}

BIN_PATH='/usr/local/bin/sentinelforge'
SHARE_PATH='/usr/local/share/sentinelforge'

usage() {
  cat <<'EOF'
Usage: uninstall.sh [--purge]

Removes the SentinelForge binary and application files. With --purge, also
deletes configuration files, backups, kernel profiles, nginx assets, and the
SentinelForge log file for a complete cleanup.
EOF
}

PURGE=false
while (($#)); do
  case "$1" in
    --purge)
      PURGE=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "SentinelForge uninstall must run as root." >&2
  exit 2
fi

cleanup_ddos_firewall() {
  if command -v iptables >/dev/null 2>&1; then
    if iptables -w -C INPUT -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
      iptables -w -D INPUT -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1 || iptables -D INPUT -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1 || true
      echo "Detached iptables INPUT hook for ${SENTINELFORGE_DDOS_CHAIN}."
    fi
    if iptables -w -C FORWARD -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
      iptables -w -D FORWARD -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1 || iptables -D FORWARD -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1 || true
      echo "Detached iptables FORWARD hook for ${SENTINELFORGE_DDOS_CHAIN}."
    fi
    if iptables -w -nL "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
      iptables -w -F "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1 || true
      iptables -w -X "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1 || true
      echo "Removed iptables chain ${SENTINELFORGE_DDOS_CHAIN}."
    fi
    if iptables -w -nL "$SENTINELFORGE_DDOS_LOG_CHAIN" >/dev/null 2>&1; then
      iptables -w -F "$SENTINELFORGE_DDOS_LOG_CHAIN" >/dev/null 2>&1 || true
      iptables -w -X "$SENTINELFORGE_DDOS_LOG_CHAIN" >/dev/null 2>&1 || true
      echo "Removed iptables chain ${SENTINELFORGE_DDOS_LOG_CHAIN}."
    fi
  fi

  if command -v ipset >/dev/null 2>&1; then
    if ipset list "$SENTINELFORGE_DDOS_IPSET" >/dev/null 2>&1; then
      ipset destroy "$SENTINELFORGE_DDOS_IPSET" 2>/dev/null || ipset flush "$SENTINELFORGE_DDOS_IPSET" 2>/dev/null || true
      echo "Destroyed ipset ${SENTINELFORGE_DDOS_IPSET}."
    fi
  fi

  if command -v nft >/dev/null 2>&1; then
    if nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1; then
      nft delete table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1 || true
      echo "Removed nftables table ${SENTINELFORGE_DDOS_TABLE}."
    fi
  fi
}

cleanup_sysctl_profiles() {
  local rerun_sysctl=0
  if [[ -f "$SENTINELFORGE_DDOS_SYSCTL_PROFILE" ]]; then
    rm -f "$SENTINELFORGE_DDOS_SYSCTL_PROFILE"
    rerun_sysctl=1
    echo "Removed ${SENTINELFORGE_DDOS_SYSCTL_PROFILE}."
  fi
  if [[ "$PURGE" == true && -f "$SENTINELFORGE_SYSCTL_PROFILE" ]]; then
    rm -f "$SENTINELFORGE_SYSCTL_PROFILE"
    rerun_sysctl=1
    echo "Removed ${SENTINELFORGE_SYSCTL_PROFILE}."
  fi
  if (( rerun_sysctl )); then
    sysctl --system >/dev/null 2>&1 || true
    echo "Reloaded sysctl settings after profile cleanup."
  fi
}

cleanup_nginx_assets() {
  if [[ -d "$SENTINELFORGE_NGINX_DIR" ]]; then
    rm -rf "$SENTINELFORGE_NGINX_DIR"
    echo "Removed nginx integration directory ${SENTINELFORGE_NGINX_DIR}."
  fi
}

cleanup_configs_and_logs() {
  if [[ "$PURGE" == true ]]; then
    if [[ -f "$SENTINELFORGE_CONFIG_FILE" ]]; then
      rm -f "$SENTINELFORGE_CONFIG_FILE"
      echo "Removed ${SENTINELFORGE_CONFIG_FILE}."
    fi
    if [[ -d "$SENTINELFORGE_BACKUP_DIR" ]]; then
      rm -rf "$SENTINELFORGE_BACKUP_DIR"
      echo "Removed backup directory ${SENTINELFORGE_BACKUP_DIR}."
    fi
    if [[ -f "$SENTINELFORGE_LOG_FILE" ]]; then
      rm -f "$SENTINELFORGE_LOG_FILE"
      echo "Removed log file ${SENTINELFORGE_LOG_FILE}."
    fi
  else
    echo "Configuration (${SENTINELFORGE_CONFIG_FILE}) and backups (${SENTINELFORGE_BACKUP_DIR}) were left untouched."
  fi
}

cleanup_ddos_firewall
cleanup_sysctl_profiles
cleanup_nginx_assets

if [[ -f "$BIN_PATH" ]]; then
  rm -f "$BIN_PATH"
  echo "Removed $BIN_PATH"
else
  echo "Binary $BIN_PATH not present."
fi

if [[ -d "$SHARE_PATH" ]]; then
  rm -rf "$SHARE_PATH"
  echo "Removed $SHARE_PATH"
else
  echo "Share directory $SHARE_PATH not present."
fi

cleanup_configs_and_logs

if [[ "$PURGE" == true ]]; then
  echo "SentinelForge purge complete."
else
  echo "SentinelForge uninstall complete."
fi
