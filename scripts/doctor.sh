#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

BACKUP_DIR=${SENTINELFORGE_BACKUP_DIR:-/etc/sentinelforge/backups}

printf 'SentinelForge doctor — YrustPd\n'

if command -v sshd >/dev/null 2>&1; then
  printf '[OK] sshd found at %s\n' "$(command -v sshd)"
else
  printf '[WARN] sshd binary not found. Install openssh-server.\n'
fi

if command -v ufw >/dev/null 2>&1; then
  printf '[OK] Firewall backend: ufw\n'
elif command -v nft >/dev/null 2>&1; then
  printf '[OK] Firewall backend: nftables\n'
elif command -v iptables >/dev/null 2>&1; then
  printf '[OK] Firewall backend: iptables\n'
else
  printf '[WARN] No firewall backend detected.\n'
fi

if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd >/dev/null 2>&1 && printf '[OK] fail2ban sshd jail query succeeded.\n' || printf '[INFO] fail2ban sshd jail not yet enabled.\n'
else
  printf '[WARN] fail2ban not installed.\n'
fi

if [[ -d "$BACKUP_DIR" ]]; then
  if [[ -w "$BACKUP_DIR" ]]; then
    printf '[OK] Backup directory writable: %s\n' "$BACKUP_DIR"
  else
    printf '[WARN] Backup directory not writable: %s\n' "$BACKUP_DIR"
  fi
else
  printf '[INFO] Backup directory %s does not exist yet. It will be created on first backup.\n' "$BACKUP_DIR"
fi

printf 'Doctor check complete.\n'
