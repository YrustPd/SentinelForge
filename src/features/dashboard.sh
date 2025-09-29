#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SentinelForge_dashboard_refresh() {
  SentinelForge_utils_info "Dashboard refresh start"
  SentinelForge_detect_refresh_basics
  SentinelForge_ssh_refresh_state
  SentinelForge_firewall_refresh_state
  SentinelForge_ddos_refresh_state
  SentinelForge_fail2ban_refresh_state
  SentinelForge_sysctl_refresh_state
  SentinelForge_updates_refresh_state
  SentinelForge_score_compute
  if [[ ${SENTINELFORGE_STATE[version_status]:-} == 'update-available' && -z ${SENTINELFORGE_STATE[version_notified]:-} ]]; then
    local msg
    printf -v msg 'A newer SentinelForge release is available.\nCurrent: %s\nLatest : %s\nUse System Maintenance → "Check for SentinelForge update" to review updates.' \
      "${SENTINELFORGE_STATE[version_local]}" "${SENTINELFORGE_STATE[version_remote]:-unknown}"
    SentinelForge_ui_show_message 'Update available' "$msg" 14 70
    SENTINELFORGE_STATE[version_notified]=1
  fi
  SentinelForge_utils_info "Dashboard refresh ready"
  SENTINELFORGE_STATE[dashboard_last_refresh]=$(date +%s)
}

SentinelForge_dashboard_refresh_if_needed() {
  local force=${1:-}
  local now
  now=$(date +%s)
  local last=${SENTINELFORGE_STATE[dashboard_last_refresh]:-0}
  local min_interval=${SENTINELFORGE_DASHBOARD_REFRESH_INTERVAL:-2}
  if [[ $force == force || $last -eq 0 ]]; then
    SentinelForge_dashboard_refresh
    return
  fi
  if (( now - last >= min_interval )); then
    SentinelForge_dashboard_refresh
  fi
}

SentinelForge_dashboard_locate_uninstall_script() {
  local -a candidates=(
    "${SENTINELFORGE_APP_ROOT}/scripts/uninstall.sh"
    "/usr/local/share/sentinelforge/scripts/uninstall.sh"
  )
  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    elif [[ -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

SentinelForge_dashboard_run_uninstall() {
  local mode=${1:-keep}
  SentinelForge_utils_require_root
  local script
  if ! script=$(SentinelForge_dashboard_locate_uninstall_script); then
    SentinelForge_ui_show_message 'Uninstall' 'Unable to locate scripts/uninstall.sh. Reinstall SentinelForge and retry.'
    return 1
  fi

  local summary
  if [[ $mode == purge ]]; then
    summary=$'This will completely remove SentinelForge, including configuration, backups, kernel profiles, nginx assets, and logs. Continue?'
  else
    summary=$'This will remove SentinelForge binaries while leaving configuration and backups intact. Continue?'
  fi
  if ! SentinelForge_ui_prompt_confirm "$summary"; then
    SentinelForge_ui_show_message 'Uninstall' 'No changes applied.'
    return 0
  fi

  local -a args=()
  if [[ $mode == purge ]]; then
    args+=("--purge")
  fi

  local output status
  if output=$(bash "$script" "${args[@]}" 2>&1); then
    status=0
  else
    status=$?
  fi
  if (( status == 0 )); then
    SentinelForge_ui_show_textbox 'Uninstall complete' "$output" 22 82
    SentinelForge_ui_show_message 'SentinelForge' 'Uninstall finished. The session will now exit.' 8 60
    exit 0
  fi
  SentinelForge_ui_show_textbox 'Uninstall failed' "$output" 22 82
  return "$status"
}

SentinelForge_dashboard_build_overview() {
  printf 'Security Score : %s (%s)\n' \
    "${SENTINELFORGE_STATE[security_score]}" "${SENTINELFORGE_STATE[security_label]}"
  printf 'Score Gauge    : %s\n' "${SENTINELFORGE_STATE[security_bar]}"
  printf 'Hostname      : %s\n' "${SENTINELFORGE_FACTS[hostname]}"
  printf 'OS            : %s\n' "${SENTINELFORGE_FACTS[os]}"
  printf 'Kernel        : %s\n' "${SENTINELFORGE_FACTS[kernel]}"
  printf 'Uptime        : %s\n' "${SENTINELFORGE_FACTS[uptime]}"
  printf 'Public Ports  : %s\n' "${SENTINELFORGE_STATE[public_listeners]}"
  printf '\nSSH\n'
  printf '  Port                  : %s\n' "${SENTINELFORGE_STATE[ssh_port]}"
  printf '  PasswordAuthentication: %s\n' "${SENTINELFORGE_STATE[ssh_password_auth]}"
  printf '  PermitRootLogin       : %s\n' "${SENTINELFORGE_STATE[ssh_permit_root]}"
  printf '  Keys ed25519:%s rsa:%s ecdsa:%s (total %s)\n' \
    "${SENTINELFORGE_STATE[ssh_key_ed25519]}" \
    "${SENTINELFORGE_STATE[ssh_key_rsa]}" \
    "${SENTINELFORGE_STATE[ssh_key_ecdsa]}" \
    "${SENTINELFORGE_STATE[ssh_key_total]}"
  printf '\nFirewall\n'
  printf '  Backend      : %s\n' "${SENTINELFORGE_STATE[firewall_backend]}"
  printf '  Enabled      : %s\n' "${SENTINELFORGE_STATE[firewall_enabled]}"
  printf '  Default In   : %s\n' "${SENTINELFORGE_STATE[firewall_default_in]}"
  printf '  SSH Allowed  : %s\n' "${SENTINELFORGE_STATE[firewall_ssh_allowed]}"
  printf '  Rate Limit   : %s\n' "${SENTINELFORGE_STATE[ssh_rate_limit]}"
  printf '\nDDoS\n'
  printf '  Guard        : %s (hooked: %s)\n' "${SENTINELFORGE_STATE[ddos_guard]}" "${SENTINELFORGE_STATE[ddos_guard_hook]}"
  printf '  Blocklist    : %s\n' "${SENTINELFORGE_STATE[ddos_blocklist]}"
  printf '  Kernel tune  : %s\n' "${SENTINELFORGE_STATE[ddos_sysctl]}"
  printf '  Nginx assets : %s\n' "${SENTINELFORGE_STATE[ddos_nginx]}"
  printf '\nFail2ban\n'
  printf '  Service      : %s\n' "${SENTINELFORGE_STATE[fail2ban_status]}"
  printf '  sshd jail    : %s\n' "${SENTINELFORGE_STATE[fail2ban_sshd]}"
  printf '  Currently banned: %s\n' "${SENTINELFORGE_STATE[fail2ban_recent_bans]}"
  printf '\nSystem\n'
  printf '  Sysctl profile        : %s\n' "${SENTINELFORGE_STATE[sysctl_applied]}"
  printf '  Unattended upgrades   : %s\n' "${SENTINELFORGE_STATE[unattended_enabled]}"
  printf '  Pending OS updates    : %s\n' "${SENTINELFORGE_STATE[pending_updates]}"
  printf '  SentinelForge version : %s (latest: %s, status: %s)\n' \
    "${SENTINELFORGE_STATE[version_local]}" \
    "${SENTINELFORGE_STATE[version_remote]:-unknown}" \
    "${SENTINELFORGE_STATE[version_status]:-unknown}"
}

SentinelForge_dashboard_build_system_summary() {
  printf 'Sysctl profile applied : %s\n' "${SENTINELFORGE_STATE[sysctl_applied]}"
  printf 'Pending OS updates     : %s\n' "${SENTINELFORGE_STATE[pending_updates]}"
  printf 'Unattended upgrades    : %s\n' "${SENTINELFORGE_STATE[unattended_enabled]}"
  printf 'SentinelForge version  : %s\n' "${SENTINELFORGE_STATE[version_local]}"
  printf 'Latest upstream version: %s\n' "${SENTINELFORGE_STATE[version_remote]:-unknown}"
  printf 'Update status          : %s\n' "${SENTINELFORGE_STATE[version_status]:-unknown}"
  printf 'Last checked           : %s\n' "${SENTINELFORGE_STATE[version_checked]:-not yet checked}"
  printf '\nUse option 4 to force an update check or option 2 to apply the sysctl baseline.\n'
}

SentinelForge_dashboard_show_overview() {
  SentinelForge_dashboard_refresh
  local overview
  overview=$(SentinelForge_dashboard_build_overview)
  SentinelForge_ui_show_textbox 'System Overview' "$overview" 24 80
}

SentinelForge_dashboard_run() {
  SentinelForge_utils_require_root
  SentinelForge_utils_info "Dashboard loop start"
  local force_next_refresh=1
  while true; do
    if (( force_next_refresh )); then
      SentinelForge_dashboard_refresh_if_needed force
      force_next_refresh=0
    else
      SentinelForge_dashboard_refresh_if_needed
    fi
    local choice
    choice=$(SentinelForge_ui_display_menu "SentinelForge Control Panel (v${SENTINELFORGE_VERSION})" \
      '1' 'View system overview' \
      '2' 'SSH management' \
      '3' 'Firewall management' \
      '4' 'DDoS protection' \
      '5' 'Fail2ban' \
      '6' 'System maintenance' \
      '7' 'Exit')
    case "$choice" in
      1)
        SentinelForge_dashboard_show_overview
        ;;
      2)
        SentinelForge_dashboard_ssh_menu
        force_next_refresh=1
        ;;
      3)
        SentinelForge_dashboard_firewall_menu
        force_next_refresh=1
        ;;
      4)
        SentinelForge_dashboard_ddos_menu
        force_next_refresh=1
        ;;
      5)
        SentinelForge_dashboard_fail2ban_menu
        force_next_refresh=1
        ;;
      6)
        SentinelForge_dashboard_system_menu
        force_next_refresh=1
        ;;
      7|'')
        SentinelForge_ui_show_message 'SentinelForge' 'Goodbye.' 7 40
        break
        ;;
    esac
  done
}

SentinelForge_dashboard_ssh_menu() {
  local refresh_needed=1
  while true; do
    if (( refresh_needed )); then
      SentinelForge_ssh_refresh_state
      refresh_needed=0
    fi
    local port_label
    printf -v port_label 'Change SSH port (current: %s)' "${SENTINELFORGE_STATE[ssh_port]:-unknown}"
    local password_state=${SENTINELFORGE_STATE[ssh_password_auth]:-unknown}
    local permit_root=${SENTINELFORGE_STATE[ssh_permit_root]:-unknown}
    local password_label
    local root_label
    if [[ ${password_state,,} == yes ]]; then
      password_state='enabled'
    elif [[ ${password_state,,} == no ]]; then
      password_state='disabled'
    fi
    if [[ ${permit_root,,} == yes ]]; then
      permit_root='enabled'
    elif [[ ${permit_root,,} == no || ${permit_root,,} == prohibit-password ]]; then
      permit_root='disabled'
    fi
    printf -v password_label 'Enable/Disable password login (%s)' "$password_state"
    printf -v root_label 'Enable/Disable PermitRootLogin (%s)' "$permit_root"
    local choice
    choice=$(SentinelForge_ui_display_menu 'SSH Management' \
      '1' 'View SSH status' \
      '2' 'Add authorized key' \
      '3' "$port_label" \
      '4' "$password_label" \
      '5' "$root_label" \
      '6' 'Back')
    case "$choice" in
      1)
        SentinelForge_ssh_show_status_panel
        ;;
      2)
        SentinelForge_ssh_add_public_key
        refresh_needed=1
        ;;
      3)
        SentinelForge_ssh_change_port
        refresh_needed=1
        ;;
      4)
        SentinelForge_ssh_toggle_password_login
        refresh_needed=1
        ;;
      5)
        SentinelForge_ssh_toggle_root_login
        refresh_needed=1
        ;;
      6|'') return ;;
    esac
  done
}

SentinelForge_dashboard_firewall_menu() {
  local refresh_needed=1
  while true; do
    if (( refresh_needed )); then
      SentinelForge_firewall_refresh_state
      refresh_needed=0
    fi
    local ssh_rate=${SENTINELFORGE_STATE[ssh_rate_limit]:-no}
    local default_in=${SENTINELFORGE_STATE[firewall_default_in]:-allow}
    local firewall_enabled=${SENTINELFORGE_STATE[firewall_enabled]:-no}
    local allow_count=${SENTINELFORGE_STATE[firewall_allow_count]:-unknown}
    local deny_count=${SENTINELFORGE_STATE[firewall_deny_count]:-unknown}
    local limit_count=${SENTINELFORGE_STATE[firewall_limit_count]:-unknown}
    local rate_label default_label guided_label show_label open_label limit_label
    if [[ ${ssh_rate,,} == yes ]]; then
      ssh_rate='enabled'
    else
      ssh_rate='disabled'
    fi
    local default_status='not added'
    case ${default_in,,} in
      deny|drop|reject) default_status='added' ;;
    esac
    local guided_status='not set up'
    if [[ ${firewall_enabled,,} == yes ]]; then
      guided_status='set up'
    fi
    local allow_display=$allow_count
    local deny_display=$deny_count
    local open_display
    if [[ $allow_count =~ ^[0-9]+$ ]]; then
      local total_allow=$allow_count
      if [[ $limit_count =~ ^[0-9]+$ ]]; then
        total_allow=$((total_allow + limit_count))
      fi
      open_display=$total_allow
    else
      allow_display='unknown'
      open_display='unknown'
    fi
    if [[ ! $deny_count =~ ^[0-9]+$ ]]; then
      deny_display='unknown'
    fi
    printf -v show_label 'Show allowed/blocked entries (allow: %s | deny: %s)' "$allow_display" "$deny_display"
    printf -v open_label 'Open port (current allow rules: %s)' "$open_display"
    printf -v limit_label 'Enable/Disable SSH rate limit (%s)' "$ssh_rate"
    printf -v default_label 'Set default incoming policy (status: %s)' "$default_status"
    printf -v guided_label 'Guided firewall setup (status: %s)' "$guided_status"
    local choice
    choice=$(SentinelForge_ui_display_menu 'Firewall Management' \
      '1' 'View firewall status' \
      '2' "$show_label" \
      '3' "$open_label" \
      '4' 'Close port' \
      '5' 'Open IP (allowlist add)' \
      '6' 'Close IP (allowlist remove)' \
      '7' "$default_label" \
      '8' "$guided_label" \
      '9' "$limit_label" \
      '10' 'Restart firewall' \
      '11' 'Back')
    case "$choice" in
      1) SentinelForge_firewall_show_status_panel ;;
      2)
        SentinelForge_firewall_show_allow_blocked
        ;;
      3)
        SentinelForge_firewall_open_port
        refresh_needed=1
        ;;
      4)
        SentinelForge_firewall_close_port
        refresh_needed=1
        ;;
      5)
        SentinelForge_firewall_allowlist_add
        refresh_needed=1
        ;;
      6)
        SentinelForge_firewall_allowlist_remove
        refresh_needed=1
        ;;
      7)
        SentinelForge_firewall_set_default_incoming
        refresh_needed=1
        ;;
      8)
        SentinelForge_firewall_apply_defaults
        refresh_needed=1
        ;;
      9)
        SentinelForge_firewall_refresh_state
        if [[ ${SENTINELFORGE_STATE[ssh_rate_limit]:-no} == 'yes' ]]; then
          SentinelForge_firewall_remove_rate_limit
        else
          SentinelForge_firewall_apply_rate_limit
        fi
        refresh_needed=1
        ;;
      10)
        SentinelForge_firewall_restart_backend
        refresh_needed=1
        ;;
      11|'') return ;;
    esac
  done
}

SentinelForge_dashboard_ddos_menu() {
  SentinelForge_ddos_menu
}

SentinelForge_dashboard_fail2ban_menu() {
  local refresh_needed=1
  while true; do
    if (( refresh_needed )); then
      SentinelForge_fail2ban_refresh_state
      refresh_needed=0
    fi
    local service_status=${SENTINELFORGE_STATE[fail2ban_status]:-unknown}
    local sshd_state=${SENTINELFORGE_STATE[fail2ban_sshd]:-no}
    local service_label
    local jail_label
    local banned_label
    local service_display=$service_status
    case ${service_status,,} in
      active|running) service_display='active' ;;
      inactive|stopped) service_display='inactive' ;;
    esac
    local jail_display=$sshd_state
    case ${sshd_state,,} in
      yes) jail_display='enabled' ;;
      no) jail_display='disabled' ;;
      pending) jail_display='pending' ;;
    esac
    printf -v service_label 'Enable/Disable Fail2ban service (current status: %s)' "$service_display"
    printf -v jail_label 'Enable/Disable SSH jail (current status: %s)' "$jail_display"
    local banned_count=${SENTINELFORGE_STATE[fail2ban_recent_bans]:-0}
    printf -v banned_label 'Show banned IPs (count: %s)' "$banned_count"
    local choice
    choice=$(SentinelForge_ui_display_menu 'Fail2ban' \
      '1' 'View Fail2ban status' \
      '2' "$banned_label" \
      '3' "$service_label" \
      '4' "$jail_label" \
      '5' 'Reapply recommended jail.local' \
      '6' 'Restart Fail2ban service' \
      '7' 'Back')
    case "$choice" in
      1) SentinelForge_fail2ban_show_status ;;
      2)
        SentinelForge_fail2ban_show_banned
        refresh_needed=1
        ;;
      3)
        if [[ ${service_status,,} == active || ${service_status,,} == running ]]; then
          SentinelForge_fail2ban_disable_service
        else
          SentinelForge_fail2ban_enable_service
        fi
        refresh_needed=1
        ;;
      4)
        if [[ ${sshd_state,,} == yes ]]; then
          SentinelForge_fail2ban_write_sshd_section false
          SentinelForge_ui_show_message 'Fail2ban' 'SSH jail disabled.'
        else
          SentinelForge_fail2ban_write_sshd_section true
          SentinelForge_ui_show_message 'Fail2ban' 'SSH jail enabled.'
        fi
        refresh_needed=1
        ;;
      5)
        SentinelForge_fail2ban_reapply_recommended
        refresh_needed=1
        ;;
      6)
        SentinelForge_fail2ban_restart_service
        refresh_needed=1
        ;;
      7|'') return ;;
    esac
  done
}

SentinelForge_dashboard_system_menu() {
  local refresh_needed=1
  while true; do
    if (( refresh_needed )); then
      SentinelForge_sysctl_refresh_state
      SentinelForge_updates_refresh_state
      refresh_needed=0
    fi
    local choice
    choice=$(SentinelForge_ui_display_menu 'System Maintenance' \
      '1' 'Show maintenance summary' \
      '2' 'Apply sysctl baseline' \
      '3' 'Enable unattended upgrades' \
      '4' 'Check for SentinelForge update' \
      '5' 'Update SentinelForge now' \
      '6' 'Uninstall SentinelForge (keep data)' \
      '7' 'Purge SentinelForge (remove all data)' \
      '8' 'Back')
    case "$choice" in
      1)
        SentinelForge_sysctl_refresh_state
        SentinelForge_updates_refresh_state force
        local summary
        summary=$(SentinelForge_dashboard_build_system_summary)
        SentinelForge_ui_show_textbox 'System maintenance' "$summary" 20 80
        ;;
      2)
        SentinelForge_sysctl_apply
        refresh_needed=1
        ;;
      3)
        SentinelForge_updates_enable_unattended
        refresh_needed=1
        ;;
      4)
        SentinelForge_updates_refresh_state force
        local summary
        summary=$(SentinelForge_dashboard_build_system_summary)
        SentinelForge_ui_show_textbox 'Update status' "$summary" 18 80
        refresh_needed=1
        ;;
      5)
        SentinelForge_updates_perform_self_update
        refresh_needed=1
        ;;
      6)
        SentinelForge_dashboard_run_uninstall keep
        return
        ;;
      7)
        SentinelForge_dashboard_run_uninstall purge
        return
        ;;
      8|'') return ;;
    esac
  done
}
