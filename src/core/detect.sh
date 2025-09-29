#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

declare -Ag SENTINELFORGE_FACTS=()

declare -Ag SENTINELFORGE_SSHD_DATA=()

SentinelForge_detect_refresh_basics() {
  SENTINELFORGE_FACTS[hostname]=$(hostname 2>/dev/null || echo 'unknown')
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    SENTINELFORGE_FACTS[os]="${PRETTY_NAME:-$NAME}"
  else
    SENTINELFORGE_FACTS[os]=$(uname -s)
  fi
  SENTINELFORGE_FACTS[kernel]=$(uname -r 2>/dev/null || echo 'unknown')
  SENTINELFORGE_FACTS[uptime]=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo 'unknown')
  SENTINELFORGE_FACTS[current_time]=$(date '+%Y-%m-%d %H:%M:%S')
}

SentinelForge_detect_package_manager() {
  local cached=${SENTINELFORGE_FACTS[package_manager]:-}
  if [[ -n $cached ]]; then
    printf '%s' "$cached"
    return 0
  fi
  local manager='unknown'
  if command -v apt-get >/dev/null 2>&1; then
    manager='apt-get'
  elif command -v apt >/dev/null 2>&1; then
    manager='apt'
  elif command -v dnf >/dev/null 2>&1; then
    manager='dnf'
  elif command -v yum >/dev/null 2>&1; then
    manager='yum'
  elif command -v zypper >/dev/null 2>&1; then
    manager='zypper'
  elif command -v pacman >/dev/null 2>&1; then
    manager='pacman'
  fi
  SENTINELFORGE_FACTS[package_manager]="$manager"
  printf '%s' "$manager"
  [[ $manager != 'unknown' ]]
}

SentinelForge_detect_primary_user() {
  if [[ -n ${SENTINELFORGE_FACTS[primary_user]:-} ]]; then
    printf '%s' "${SENTINELFORGE_FACTS[primary_user]}"
    return 0
  fi
  local primary=${SUDO_USER:-}
  if [[ -z "$primary" || "$primary" == "root" ]]; then
    primary=${PRIMARY_USER_OVERRIDE:-${USERNAME:-$USER}}
    if [[ "$primary" == "root" ]]; then
      local last
      last=$(logname 2>/dev/null || true)
      if [[ -n "$last" && "$last" != "root" ]]; then
        primary=$last
      fi
    fi
  fi
  SENTINELFORGE_FACTS[primary_user]="$primary"
  SENTINELFORGE_FACTS[primary_home]=$(eval echo "~${primary}" 2>/dev/null || echo '/root')
  printf '%s' "$primary"
}

SentinelForge_detect_sshd_path() {
  if [[ -n ${SENTINELFORGE_FACTS[sshd_path]:-} && -x ${SENTINELFORGE_FACTS[sshd_path]} ]]; then
    printf '%s' "${SENTINELFORGE_FACTS[sshd_path]}"
    return 0
  fi
  local path
  for path in /usr/sbin/sshd /usr/local/sbin/sshd; do
    if [[ -x "$path" ]]; then
      SENTINELFORGE_FACTS[sshd_path]="$path"
      printf '%s' "$path"
      return 0
    fi
  done
  if command -v sshd >/dev/null 2>&1; then
    path=$(command -v sshd)
    SENTINELFORGE_FACTS[sshd_path]="$path"
    printf '%s' "$path"
    return 0
  fi
  printf ''
  return 1
}

SentinelForge_detect_sshd_config() {
  SENTINELFORGE_FACTS[sshd_config]='/etc/ssh/sshd_config'
  printf '%s' "${SENTINELFORGE_FACTS[sshd_config]}"
}

SentinelForge_detect_sshd_test_config() {
  local sshd_path
  sshd_path=$(SentinelForge_detect_sshd_path) || return 1
  if [[ -z "$sshd_path" ]]; then
    return 1
  fi
  declare -gA SENTINELFORGE_SSHD_DATA=()
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local key=${line%% *}
    local value=${line#* }
    SENTINELFORGE_SSHD_DATA["$key"]="$value"
  done < <("$sshd_path" -T 2>/dev/null || true)
}

SentinelForge_detect_current_ssh_port() {
  SentinelForge_detect_sshd_test_config
  local port=${SENTINELFORGE_SSHD_DATA[port]:-22}
  printf '%s' "$port"
}

SentinelForge_detect_firewall_backend() {
  local backend=${SENTINELFORGE_FACTS[firewall_backend]:-}
  if [[ -n "$backend" ]]; then
    printf '%s' "$backend"
    return 0
  fi
  if command -v ufw >/dev/null 2>&1; then
    backend='ufw'
  elif command -v nft >/dev/null 2>&1; then
    backend='nftables'
  elif command -v iptables >/dev/null 2>&1; then
    backend='iptables'
  else
    backend='none'
  fi
  SENTINELFORGE_FACTS[firewall_backend]="$backend"
  printf '%s' "$backend"
}

SentinelForge_detect_public_listeners() {
  local -a listeners=()
  if command -v ss >/dev/null 2>&1; then
    while IFS= read -r line; do
      listeners+=("$line")
    done < <(ss -tulpen 2>/dev/null | awk 'NR>1 && ($5 ~ /0.0.0.0|::/) {print $1" "$5" -> "$7}')
  fi
  printf '%s\n' "${listeners[@]}"
}

SentinelForge_detect_top_remote_ips() {
  local -a lines=()
  if command -v ss >/dev/null 2>&1; then
    while IFS= read -r line; do
      lines+=("$line")
    done < <(ss -tn state established 2>/dev/null | awk 'NR>1 {split($5,ip,":"); counts[ip[1]]++} END {for (i in counts) printf "%s %s\n", counts[i], i}' | sort -rn | head -n5)
  fi
  printf '%s\n' "${lines[@]}"
}

SentinelForge_detect_pending_updates() {
  local manager
  manager=$(SentinelForge_detect_package_manager)
  case "$manager" in
    apt-get|apt)
      local pending
      pending=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / {count++} END {print count+0}')
      printf '%s' "${pending:-0}"
      ;;
    dnf)
      if command -v dnf >/dev/null 2>&1; then
        local count
        count=$(dnf --quiet check-update 2>/dev/null | awk 'NF==2 && $2 ~ /^[0-9]/ {c++} END {print c+0}' 2>/dev/null || true)
        printf '%s' "${count:-0}"
      else
        printf '0'
        return 1
      fi
      ;;
    yum)
      if command -v yum >/dev/null 2>&1; then
        local count
        count=$(yum --quiet check-update 2>/dev/null | awk 'NF==2 && $2 ~ /^[0-9]/ {c++} END {print c+0}' 2>/dev/null || true)
        printf '%s' "${count:-0}"
      else
        printf '0'
        return 1
      fi
      ;;
    zypper)
      if command -v zypper >/dev/null 2>&1; then
        if zypper --non-interactive refresh >/dev/null 2>&1; then
          local count
          count=$(zypper --non-interactive list-updates 2>/dev/null | awk 'NR>2 {c++} END {print c+0}' 2>/dev/null || true)
          printf '%s' "${count:-0}"
        else
          printf '0'
          return 1
        fi
      else
        printf '0'
        return 1
      fi
      ;;
    pacman)
      if command -v checkupdates >/dev/null 2>&1; then
        local count
        count=$(checkupdates 2>/dev/null | wc -l | tr -d '[:space:]' 2>/dev/null || true)
        printf '%s' "${count:-0}"
      else
        printf '0'
        return 1
      fi
      ;;
    *)
      printf '0'
      return 1
      ;;
  esac
}

SentinelForge_detect_unattended_enabled() {
  local manager
  manager=$(SentinelForge_detect_package_manager)
  case "$manager" in
    apt-get|apt)
      if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
        printf 'yes'
      else
        printf 'no'
      fi
      ;;
    *)
      printf 'unknown'
      return 1
      ;;
  esac
}
