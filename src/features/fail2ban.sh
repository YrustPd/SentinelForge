#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SentinelForge_fail2ban_refresh_state() {
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    SENTINELFORGE_STATE[fail2ban_status]='not-installed'
    SENTINELFORGE_STATE[fail2ban_sshd]='no'
    SENTINELFORGE_STATE[fail2ban_recent_bans]='0'
    unset SENTINELFORGE_STATE[fail2ban_banned_ips]
    return 1
  fi
  local status
  status=$(systemctl is-active fail2ban 2>/dev/null || echo 'inactive')
  SENTINELFORGE_STATE[fail2ban_status]="$status"
  local sshd_state='no'
  if fail2ban-client status sshd >/dev/null 2>&1; then
    sshd_state='yes'
  else
    local jail_file='/etc/fail2ban/jail.local'
    if [[ -f "$jail_file" ]] && grep -Eq '^\[sshd\]' "$jail_file"; then
      if awk 'BEGIN{in=0}
               /^\[sshd\]/{in=1; next}
               (/^\[/ && in==1){exit}
               in==1 && tolower($0) ~ /^enabled[[:space:]]*=/{print tolower($0); exit}' "$jail_file" | grep -q 'true'; then
        sshd_state='pending'
      fi
    fi
  fi
  SENTINELFORGE_STATE[fail2ban_sshd]="$sshd_state"
  local summary
  summary=$(fail2ban-client status sshd 2>/dev/null || true)
  local banned='0'
  local banned_list=''
  if [[ -n $summary ]]; then
    local parsed
    parsed=$(awk -F': ' '/Currently banned/ {print $2}' <<<"$summary" | tr -d '[:space:]' || true)
    if [[ -n $parsed ]]; then
      banned=$parsed
    fi
    local list_line
    list_line=$(awk -F': ' '/Banned IP list/ {print $2}' <<<"$summary" | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//' || true)
    if [[ -n $list_line ]]; then
      banned_list=$(tr ' ' '\n' <<<"$list_line" | sed '/^$/d')
    fi
  fi
  SENTINELFORGE_STATE[fail2ban_recent_bans]="$banned"
  if [[ -n $banned_list ]]; then
    SENTINELFORGE_STATE[fail2ban_banned_ips]="$banned_list"
  else
    unset SENTINELFORGE_STATE[fail2ban_banned_ips]
  fi
}

SentinelForge_fail2ban_enable_service() {
  SentinelForge_utils_require_root
  systemctl enable fail2ban >/dev/null 2>&1 || true
  if systemctl restart fail2ban >/dev/null 2>&1 || systemctl start fail2ban >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'Fail2ban' 'Fail2ban service enabled and started.'
    return 0
  fi
  SentinelForge_ui_show_message 'Fail2ban' 'Failed to start Fail2ban service. Review logs.'
  return 1
}

SentinelForge_fail2ban_disable_service() {
  SentinelForge_utils_require_root
  systemctl stop fail2ban >/dev/null 2>&1 || true
  systemctl disable fail2ban >/dev/null 2>&1 || true
  SentinelForge_ui_show_message 'Fail2ban' 'Fail2ban service stopped and disabled.'
}

SentinelForge_fail2ban_restart_service() {
  SentinelForge_utils_require_root
  if systemctl restart fail2ban >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'Fail2ban' 'Fail2ban service restarted.'
    return 0
  fi
  SentinelForge_ui_show_message 'Fail2ban' 'Failed to restart Fail2ban service. Check journalctl -u fail2ban.'
  return 1
}

SentinelForge_fail2ban_write_sshd_section() {
  SentinelForge_utils_require_root
  local enabled_flag=$1
  local ssh_port
  ssh_port=$(SentinelForge_detect_current_ssh_port)
  local jail_file='/etc/fail2ban/jail.local'
  mkdir -p /etc/fail2ban
  local tmp
  tmp=$(mktemp "${TMPDIR:-/tmp}/sentinelforge-fail2ban.XXXXXX")
  if [[ -f "$jail_file" ]]; then
    awk 'BEGIN{in=0}
         /^\[sshd\]/{in=1; next}
         (/^\[/ && in==1){in=0}
         in==0 {print $0}' "$jail_file" >"$tmp"
  else
    : >"$tmp"
  fi
  cat <<EOF >>"$tmp"

[sshd]
enabled = ${enabled_flag}
port = ${ssh_port}
filter = sshd
maxretry = 5
findtime = 600
bantime = 3600
backend = systemd
EOF
  SentinelForge_utils_backup_file "$jail_file" 'systemctl restart fail2ban' >/dev/null || true
  mv "$tmp" "$jail_file"
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || systemctl start fail2ban >/dev/null 2>&1 || true
}

SentinelForge_fail2ban_reapply_recommended() {
  SentinelForge_utils_require_root
  local ssh_port
  ssh_port=$(SentinelForge_detect_current_ssh_port)
  local enable_nginx='no'
  if [[ -d /etc/nginx ]]; then
    if SentinelForge_ui_prompt_confirm "Detected nginx. Enable nginx-http-auth jail?"; then
      enable_nginx='yes'
    fi
  fi
  local jail_file='/etc/fail2ban/jail.local'
  mkdir -p /etc/fail2ban
  SentinelForge_utils_backup_file "$jail_file" 'systemctl restart fail2ban' >/dev/null || true
  local template="${SENTINELFORGE_SHARE_ROOT}/templates/fail2ban-jail.local"
  local content
  if [[ -f "$template" ]]; then
    content=$(sed "s/{{SSH_PORT}}/${ssh_port}/g" "$template")
  else
    read -r -d '' content <<CONF
[sshd]
enabled = true
port = ${ssh_port}
filter = sshd
maxretry = 5
findtime = 600
bantime = 3600
backend = systemd
CONF
  fi
  if [[ "$enable_nginx" == 'yes' ]]; then
    content+=$'\n[nginx-http-auth]\n'
    content+=$'enabled = true\n'
    content+=$'port = http,https\n'
    content+=$'filter = nginx-http-auth\n'
    content+=$'maxretry = 6\n'
    content+=$'findtime = 600\n'
    content+=$'bantime = 3600\n'
  fi
  printf '%s\n' "$content" >"$jail_file"
  systemctl enable fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || systemctl start fail2ban >/dev/null 2>&1 || true
  SentinelForge_ui_show_message 'Fail2ban' "Fail2ban jail.local reapplied. SSH jail configured on port ${ssh_port}."
}

SentinelForge_fail2ban_configure() {
  SentinelForge_utils_require_root
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'Fail2ban' 'Fail2ban is not installed. Install it first (apt-get install fail2ban).'
    return 1
  fi
  local refresh_needed=1
  while true; do
    if (( refresh_needed )); then
      SentinelForge_fail2ban_refresh_state
      refresh_needed=0
    fi
    local status=${SENTINELFORGE_STATE[fail2ban_status]:-unknown}
    local sshd_state=${SENTINELFORGE_STATE[fail2ban_sshd]:-no}
    local banned_display=${SENTINELFORGE_STATE[fail2ban_recent_bans]:-0}
    local choice
    choice=$(SentinelForge_ui_display_menu 'Fail2ban Configuration' \
      '1' "Enable Fail2ban service (current status: ${status})" \
      '2' 'Disable Fail2ban service' \
      '3' "Show banned IPs (count: ${banned_display})" \
      '4' "Enable SSH jail" \
      '5' 'Disable SSH jail' \
      '6' 'Restart Fail2ban service' \
      '7' 'Reapply recommended jail.local' \
      '8' 'Back')
    case "$choice" in
      1)
        SentinelForge_fail2ban_enable_service
        refresh_needed=1
        ;;
      2)
        SentinelForge_fail2ban_disable_service
        refresh_needed=1
        ;;
      3)
        SentinelForge_fail2ban_show_banned
        refresh_needed=1
        ;;
      4)
        if [[ $sshd_state == 'yes' ]]; then
          SentinelForge_ui_show_message 'Fail2ban' 'SSH jail already active.'
        else
          SentinelForge_fail2ban_write_sshd_section true
          SentinelForge_ui_show_message 'Fail2ban' 'SSH jail enabled.'
        fi
        refresh_needed=1
        ;;
      5)
        SentinelForge_fail2ban_write_sshd_section false
        SentinelForge_ui_show_message 'Fail2ban' 'SSH jail disabled.'
        refresh_needed=1
        ;;
      6)
        SentinelForge_fail2ban_restart_service
        refresh_needed=1
        ;;
      7)
        SentinelForge_fail2ban_reapply_recommended
        refresh_needed=1
        ;;
      8|'') return ;;
    esac
  done
}

SentinelForge_fail2ban_show_status() {
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'Fail2ban' 'Fail2ban not installed.'
    return
  fi
  local report
  report=$(fail2ban-client status 2>/dev/null || echo 'fail2ban-client status unavailable')
  report+=$'\n\nRecent journal (last 40 lines):\n'
  report+=$(journalctl -u fail2ban -n 40 --no-pager 2>/dev/null || echo 'journalctl unavailable')
  SentinelForge_ui_show_textbox 'Fail2ban status' "$report" 22 78
}

SentinelForge_fail2ban_show_banned() {
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'Fail2ban' 'Fail2ban not installed.'
    return
  fi
  SentinelForge_fail2ban_refresh_state
  local list=${SENTINELFORGE_STATE[fail2ban_banned_ips]:-}
  if [[ -z $list ]]; then
    SentinelForge_ui_show_message 'Fail2ban' 'No IPs are currently banned by the sshd jail.'
    return
  fi
  local formatted='Currently banned IPs (sshd jail):\n\n'
  formatted+=$(printf '%s\n' "$list")
  SentinelForge_ui_show_textbox 'Fail2ban banned IPs' "$formatted" 20 70
}
