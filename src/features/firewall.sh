#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SentinelForge_firewall_refresh_state() {
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  SENTINELFORGE_STATE[firewall_backend]="$backend"
  SENTINELFORGE_STATE[firewall_enabled]='no'
  SENTINELFORGE_STATE[firewall_default_in]='allow'
  SENTINELFORGE_STATE[firewall_default_out]='allow'
  SENTINELFORGE_STATE[firewall_ssh_allowed]='no'
  SENTINELFORGE_STATE[ssh_rate_limit]='no'
  SENTINELFORGE_STATE[firewall_allow_count]='unknown'
  SENTINELFORGE_STATE[firewall_deny_count]='unknown'
  SENTINELFORGE_STATE[firewall_limit_count]='unknown'

  local ssh_port=${SENTINELFORGE_STATE[ssh_port]:-$(SentinelForge_detect_current_ssh_port)}
  case "$backend" in
    ufw)
      local verbose rules
      verbose=$(ufw status verbose 2>/dev/null || true)
      rules=$(ufw status numbered 2>/dev/null || true)
      if grep -q 'Status: active' <<<"$verbose"; then
        SENTINELFORGE_STATE[firewall_enabled]='yes'
      fi
      SENTINELFORGE_STATE[firewall_default_in]=$(awk -F'[ ,]+' '/Default:/ && /incoming/ {print tolower($2)}' <<<"$verbose" | head -n1)
      SENTINELFORGE_STATE[firewall_default_out]=$(awk -F'[ ,]+' '/Default:/ && /outgoing/ {print tolower($2)}' <<<"$verbose" | head -n1)
      if grep -Eq "${ssh_port}/tcp[[:space:]]+(ALLOW|LIMIT)" <<<"$rules"; then
        SENTINELFORGE_STATE[firewall_ssh_allowed]='yes'
      fi
      if grep -Eq "${ssh_port}/tcp[[:space:]]+LIMIT" <<<"$rules"; then
        SENTINELFORGE_STATE[ssh_rate_limit]='yes'
      fi
      local allow_count deny_count limit_count
      allow_count=$(grep -c 'ALLOW' <<<"$rules" || true)
      deny_count=$(grep -c 'DENY' <<<"$rules" || true)
      limit_count=$(grep -c 'LIMIT' <<<"$rules" || true)
      SENTINELFORGE_STATE[firewall_allow_count]="$allow_count"
      SENTINELFORGE_STATE[firewall_deny_count]="$deny_count"
      SENTINELFORGE_STATE[firewall_limit_count]="$limit_count"
      ;;
    nftables)
      if nft list ruleset >/dev/null 2>&1; then
        SENTINELFORGE_STATE[firewall_enabled]='yes'
        if nft list ruleset | grep -q 'policy drop'; then
          SENTINELFORGE_STATE[firewall_default_in]='drop'
        fi
        if nft list ruleset | grep -q "dport ${ssh_port}"; then
          SENTINELFORGE_STATE[firewall_ssh_allowed]='yes'
        fi
        if nft list ruleset | grep -qi 'limit rate'; then
          SENTINELFORGE_STATE[ssh_rate_limit]='yes'
        fi
      fi
      ;;
    iptables)
      if iptables -S >/dev/null 2>&1; then
        SENTINELFORGE_STATE[firewall_enabled]='yes'
        SENTINELFORGE_STATE[firewall_default_in]=$(iptables -S INPUT 2>/dev/null | awk '/^-P INPUT/ {print tolower($3)}' | head -n1)
        SENTINELFORGE_STATE[firewall_default_out]=$(iptables -S OUTPUT 2>/dev/null | awk '/^-P OUTPUT/ {print tolower($3)}' | head -n1)
        if iptables -C INPUT -p tcp --dport "$ssh_port" -j ACCEPT 2>/dev/null; then
          SENTINELFORGE_STATE[firewall_ssh_allowed]='yes'
        fi
        if iptables -C INPUT -p tcp --dport "$ssh_port" -m connlimit --connlimit-above 10 -j REJECT 2>/dev/null; then
          SENTINELFORGE_STATE[ssh_rate_limit]='yes'
        fi
      fi
      ;;
    none)
      :
      ;;
  esac
}

SentinelForge_firewall_bool_toggle() {
  local value=${1:-no}
  if [[ ${value,,} == 'yes' ]]; then
    printf '%s' 'no'
  else
    printf '%s' 'yes'
  fi
}

SentinelForge_firewall_bool_label() {
  local value=${1:-no}
  if [[ ${value,,} == 'yes' ]]; then
    printf '%s' 'Yes'
  else
    printf '%s' 'No'
  fi
}

SentinelForge_firewall_guided_cancel() {
  local message=$1
  SENTINELFORGE_FIREWALL_GUIDED_APPLIED=0
  SENTINELFORGE_FIREWALL_GUIDED_LOG=''
  SentinelForge_ui_show_message 'Firewall' "$message"
}

SentinelForge_firewall_prompt_port() {
  local prompt=${1:-'Enter port number (1-65535): '}
  local default_value=${2:-}
  local port
  port=$(SentinelForge_ui_prompt_input "$prompt" "$default_value")
  if [[ ${SENTINELFORGE_UI_LAST_STATUS:-ok} == 'cancel' ]]; then
    return 1
  fi
  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    SentinelForge_ui_show_message 'Firewall' 'Invalid port selected.'
    return 1
  fi
  local port_num=$port
  if (( port_num < 1 || port_num > 65535 )); then
    SentinelForge_ui_show_message 'Firewall' 'Invalid port selected.'
    return 1
  fi
  printf '%s' "$port"
}

SentinelForge_firewall_prompt_protocol() {
  local choice
  choice=$(SentinelForge_ui_display_menu 'Select protocol' \
    '1' 'TCP' \
    '2' 'UDP' \
    '3' 'Both')
  case "$choice" in
    1) printf '%s' 'tcp' ;;
    2) printf '%s' 'udp' ;;
    3|'') printf '%s' 'both' ;;
  esac
}

SentinelForge_firewall_set_default_incoming() {
  SentinelForge_utils_require_root
  SentinelForge_firewall_refresh_state
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  if [[ $backend != 'ufw' ]]; then
    SentinelForge_ui_show_message 'Firewall' 'Default incoming policy management is available only for UFW.'
    return 1
  fi
  local current=${SENTINELFORGE_STATE[firewall_default_in]:-allow}
  local choice
  choice=$(SentinelForge_ui_display_menu 'UFW Default Incoming Policy' \
    '1' "Set to deny (current: ${current})" \
    '2' 'Set to allow' \
    '3' 'Back')
  case "$choice" in
    1)
      if ufw default deny incoming >/dev/null 2>&1; then
        SENTINELFORGE_STATE[firewall_default_in]='deny'
        SentinelForge_ui_show_message 'Firewall' 'UFW default incoming policy set to deny.'
      else
        SentinelForge_ui_show_message 'Firewall' 'Failed to set UFW default incoming policy to deny.'
        return 1
      fi
      ;;
    2)
      if ufw default allow incoming >/dev/null 2>&1; then
        SENTINELFORGE_STATE[firewall_default_in]='allow'
        SentinelForge_ui_show_message 'Firewall' 'UFW default incoming policy set to allow.'
      else
        SentinelForge_ui_show_message 'Firewall' 'Failed to set UFW default incoming policy to allow.'
        return 1
      fi
      ;;
    *) return 0 ;;
  esac
  return 0
}

SentinelForge_firewall_ensure_port() {
  SentinelForge_utils_require_root
  local port=$1
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  case "$backend" in
    ufw)
      if ! ufw status numbered 2>/dev/null | grep -F "${port}/tcp" | grep -q 'ALLOW'; then
        printf '%sAllowing port %s via UFW before continuing.%s\n' \
          "$SENTINELFORGE_COLOR_CYAN" "$port" "$SENTINELFORGE_COLOR_RESET"
        ufw allow "${port}/tcp" >/dev/null 2>&1 || ufw allow "$port" >/dev/null 2>&1
      fi
      ;;
    nftables)
      if ! nft list ruleset 2>/dev/null | grep -q "dport ${port}"; then
        printf '%sAllowing port %s using nftables (inet filter input).%s\n' \
          "$SENTINELFORGE_COLOR_CYAN" "$port" "$SENTINELFORGE_COLOR_RESET"
        nft add rule inet filter input tcp dport ${port} ct state new accept >/dev/null 2>&1 || true
      fi
      ;;
    iptables)
      if ! iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
        printf '%sAllowing port %s via iptables before continuing.%s\n' \
          "$SENTINELFORGE_COLOR_CYAN" "$port" "$SENTINELFORGE_COLOR_RESET"
        iptables -I INPUT -p tcp --dport "$port" -m state --state NEW -j ACCEPT
      fi
      ;;
    none)
      printf '%sNo firewall backend detected. Manually confirm remote access on port %s.%s\n' \
        "$SENTINELFORGE_COLOR_YELLOW" "$port" "$SENTINELFORGE_COLOR_RESET"
      ;;
  esac
}

SentinelForge_firewall_open_port() {
  SentinelForge_utils_require_root
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  if [[ $backend == 'none' ]]; then
    SentinelForge_ui_show_message 'Firewall' 'No firewall backend detected. Configure a firewall first.'
    return 1
  fi
  local port
  port=$(SentinelForge_firewall_prompt_port 'Open which port (1-65535)?') || return 1
  local proto
  proto=$(SentinelForge_firewall_prompt_protocol)
  local message=''
  case "$backend" in
    ufw)
      if [[ $proto == 'both' || $proto == 'tcp' ]]; then
        ufw allow "${port}/tcp" >/dev/null 2>&1
      fi
      if [[ $proto == 'both' || $proto == 'udp' ]]; then
        ufw allow "${port}/udp" >/dev/null 2>&1
      fi
      message="UFW allow rule added for port ${port} (${proto})."
      ;;
    nftables)
      if ! nft list table inet sentinelforge >/dev/null 2>&1; then
        SentinelForge_ui_show_message 'Firewall' 'Run guided firewall setup before managing ports with nftables.'
        return 1
      fi
      if [[ $proto == 'both' || $proto == 'tcp' ]]; then
        nft add rule inet sentinelforge input tcp dport ${port} ct state new accept >/dev/null 2>&1 || true
      fi
      if [[ $proto == 'both' || $proto == 'udp' ]]; then
        nft add rule inet sentinelforge input udp dport ${port} ct state new accept >/dev/null 2>&1 || true
      fi
      message="nftables accept rule added for port ${port} (${proto})."
      ;;
    iptables)
      if [[ $proto == 'both' || $proto == 'tcp' ]]; then
        iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || \
          iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
      fi
      if [[ $proto == 'both' || $proto == 'udp' ]]; then
        iptables -C INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1 || \
          iptables -I INPUT -p udp --dport "$port" -j ACCEPT
      fi
      message="iptables accept rule added for port ${port} (${proto})."
      ;;
  esac
  SentinelForge_ui_show_message 'Firewall' "$message"
}

SentinelForge_firewall_close_port() {
  SentinelForge_utils_require_root
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  if [[ $backend == 'none' ]]; then
    SentinelForge_ui_show_message 'Firewall' 'No firewall backend detected. Configure a firewall first.'
    return 1
  fi
  local port
  port=$(SentinelForge_firewall_prompt_port 'Close which port (1-65535)?') || return 1
  local proto
  proto=$(SentinelForge_firewall_prompt_protocol)
  local message=''
  case "$backend" in
    ufw)
      local removed=0
      if [[ $proto == 'both' || $proto == 'tcp' ]]; then
        ufw --force delete allow "${port}/tcp" >/dev/null 2>&1 && removed=1
      fi
      if [[ $proto == 'both' || $proto == 'udp' ]]; then
        ufw --force delete allow "${port}/udp" >/dev/null 2>&1 && removed=1
      fi
      if (( removed )); then
        message="Removed UFW allow rule(s) for port ${port} (${proto})."
      else
        message="No matching UFW allow rule for port ${port}."
      fi
      ;;
    nftables)
      if ! nft list table inet sentinelforge >/dev/null 2>&1; then
        SentinelForge_ui_show_message 'Firewall' 'Run guided firewall setup before managing ports with nftables.'
        return 1
      fi
      local removed=0
      if [[ $proto == 'both' || $proto == 'tcp' ]]; then
        local handle
        handle=$(nft -a list chain inet sentinelforge input | awk -v p="$port" '/ tcp / && /dport/ && $0 ~ p && /accept/ {print $NF; exit}') || handle=""
        if [[ -n $handle ]]; then
          nft delete rule inet sentinelforge input handle "$handle" >/dev/null 2>&1 || true
          removed=1
        fi
      fi
      if [[ $proto == 'both' || $proto == 'udp' ]]; then
        local handle
        handle=$(nft -a list chain inet sentinelforge input | awk -v p="$port" '/ udp / && /dport/ && $0 ~ p && /accept/ {print $NF; exit}') || handle=""
        if [[ -n $handle ]]; then
          nft delete rule inet sentinelforge input handle "$handle" >/dev/null 2>&1 || true
          removed=1
        fi
      fi
      if (( removed )); then
        message="Removed nftables accept rule(s) for port ${port} (${proto})."
      else
        message='No matching nftables rules found.'
      fi
      ;;
    iptables)
      local removed=0
      if [[ $proto == 'both' || $proto == 'tcp' ]]; then
        if iptables -C INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
          iptables -D INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1
          removed=1
        fi
      fi
      if [[ $proto == 'both' || $proto == 'udp' ]]; then
        if iptables -C INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
          iptables -D INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
          removed=1
        fi
      fi
      if (( removed )); then
        message="Removed iptables accept rule(s) for port ${port} (${proto})."
      else
        message="No matching iptables accept rule for port ${port}."
      fi
      ;;
  esac
  SentinelForge_ui_show_message 'Firewall' "$message"
}

SentinelForge_firewall_restart_backend() {
  SentinelForge_utils_require_root
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  local message=''
  case "$backend" in
    ufw)
      if ufw reload >/dev/null 2>&1; then
        message='UFW firewall reloaded.'
      else
        message='Failed to reload UFW. Review ufw status manually.'
      fi
      ;;
    nftables)
      if systemctl reload nftables >/dev/null 2>&1; then
        message='nftables service reloaded.'
      elif systemctl restart nftables >/dev/null 2>&1; then
        message='nftables service restarted.'
      else
        message='Unable to reload nftables automatically. Use systemctl reload nftables.'
      fi
      ;;
    iptables)
      if command -v netfilter-persistent >/dev/null 2>&1; then
        if netfilter-persistent reload >/dev/null 2>&1; then
          message='netfilter-persistent reloaded current iptables rules.'
        else
          message='netfilter-persistent reload failed. Review iptables state.'
        fi
      elif systemctl restart iptables >/dev/null 2>&1; then
        message='iptables service restarted.'
      else
        message='No iptables service found to restart automatically.'
      fi
      ;;
    none)
      message='No firewall backend detected to restart.'
      ;;
  esac
  SentinelForge_ui_show_message 'Firewall' "$message"
}

SentinelForge_firewall_guided_setup_ufw() {
  local ssh_port=$1
  if ! SentinelForge_ui_prompt_confirm "Proceed with guided UFW setup?"; then
    SentinelForge_firewall_guided_cancel 'UFW guided setup aborted.'
    return 0
  fi
  local allow_http='no'
  local allow_https='no'
  local default_deny='no'
  local enable_now='yes'
  while true; do
    local choice
    choice=$(SentinelForge_ui_display_menu 'UFW Guided Setup' \
      '1' "Allow HTTP (80/tcp): $(SentinelForge_firewall_bool_label "$allow_http")" \
      '2' "Allow HTTPS (443/tcp): $(SentinelForge_firewall_bool_label "$allow_https")" \
      '3' "Set default incoming policy to deny: $(SentinelForge_firewall_bool_label "$default_deny")" \
      '4' "Enable UFW now: $(SentinelForge_firewall_bool_label "$enable_now")" \
      '5' 'Review & apply changes' \
      '6' 'Cancel')
    case "$choice" in
      1) allow_http=$(SentinelForge_firewall_bool_toggle "$allow_http") ;;
      2) allow_https=$(SentinelForge_firewall_bool_toggle "$allow_https") ;;
      3) default_deny=$(SentinelForge_firewall_bool_toggle "$default_deny") ;;
      4) enable_now=$(SentinelForge_firewall_bool_toggle "$enable_now") ;;
      5)
        local review
        printf -v review 'SSH port        : %s\nAllow HTTP      : %s\nAllow HTTPS     : %s\nDefault incoming: %s\nEnable UFW now  : %s\n' \
          "$ssh_port" \
          "$(SentinelForge_firewall_bool_label "$allow_http")" \
          "$(SentinelForge_firewall_bool_label "$allow_https")" \
          "$(SentinelForge_firewall_bool_label "$default_deny")" \
          "$(SentinelForge_firewall_bool_label "$enable_now")"
        SentinelForge_ui_show_textbox 'Pending UFW changes' "$review" 18 72
        if SentinelForge_ui_prompt_confirm 'Apply these UFW changes now?' false; then
          break
        fi
        ;;
      6|'')
        SentinelForge_firewall_guided_cancel 'UFW guided setup cancelled.'
        return 0
        ;;
    esac
  done

  local log=''
  SentinelForge_firewall_ensure_port "$ssh_port"
  log+=$'Ensured SSH port remains accessible.\n'
  if [[ $allow_http == 'yes' ]]; then
    ufw allow 80/tcp >/dev/null 2>&1
    log+=$'Allowed HTTP (80/tcp).\n'
  else
    log+=$'HTTP (80/tcp) left unchanged.\n'
  fi
  if [[ $allow_https == 'yes' ]]; then
    ufw allow 443/tcp >/dev/null 2>&1
    log+=$'Allowed HTTPS (443/tcp).\n'
  else
    log+=$'HTTPS (443/tcp) left unchanged.\n'
  fi
  if [[ $default_deny == 'yes' ]]; then
    ufw default deny incoming >/dev/null 2>&1
    log+=$'Default incoming policy set to deny.\n'
  else
    log+=$'Default incoming policy unchanged.\n'
  fi
  if [[ $enable_now == 'yes' ]]; then
    ufw enable <<<"y" >/dev/null 2>&1
    log+=$'UFW enabled.\n'
  else
    log+=$'UFW left disabled.\n'
  fi
  SENTINELFORGE_FIREWALL_GUIDED_APPLIED=1
  SENTINELFORGE_FIREWALL_GUIDED_LOG="$log"
}

SentinelForge_firewall_guided_setup_nftables() {
  local ssh_port=$1
  if ! SentinelForge_ui_prompt_confirm "Proceed with nftables hardening (inet filter)?"; then
    SentinelForge_firewall_guided_cancel 'nftables guided setup aborted.'
    return 0
  fi
  local allow_http='no'
  local allow_https='no'
  while true; do
    local choice
    choice=$(SentinelForge_ui_display_menu 'nftables Guided Setup' \
      '1' "Allow HTTP (80/tcp): $(SentinelForge_firewall_bool_label "$allow_http")" \
      '2' "Allow HTTPS (443/tcp): $(SentinelForge_firewall_bool_label "$allow_https")" \
      '3' 'Review & apply changes' \
      '4' 'Cancel')
    case "$choice" in
      1) allow_http=$(SentinelForge_firewall_bool_toggle "$allow_http") ;;
      2) allow_https=$(SentinelForge_firewall_bool_toggle "$allow_https") ;;
      3)
        local review
        printf -v review 'SSH port : %s\nAllow HTTP : %s\nAllow HTTPS: %s\n' \
          "$ssh_port" \
          "$(SentinelForge_firewall_bool_label "$allow_http")" \
          "$(SentinelForge_firewall_bool_label "$allow_https")"
        SentinelForge_ui_show_textbox 'Pending nftables changes' "$review" 16 68
        if SentinelForge_ui_prompt_confirm 'Apply these nftables changes now?' false; then
          break
        fi
        ;;
      4|'')
        SentinelForge_firewall_guided_cancel 'nftables guided setup cancelled.'
        return 0
        ;;
    esac
  done

  local log=''
  nft add table inet sentinelforge >/dev/null 2>&1 || true
  nft add chain inet sentinelforge input { type filter hook input priority 0 \; policy drop \; } >/dev/null 2>&1 || true
  nft add rule inet sentinelforge input ct state established,related accept >/dev/null 2>&1 || true
  nft add rule inet sentinelforge input iif lo accept >/dev/null 2>&1 || true
  nft add rule inet sentinelforge input tcp dport ${ssh_port} ct state new accept >/dev/null 2>&1 || true
  log+=$'Ensured nftables base policy and SSH allowance.\n'
  if [[ $allow_http == 'yes' ]]; then
    nft add rule inet sentinelforge input tcp dport 80 ct state new accept >/dev/null 2>&1 || true
    log+=$'Allowed HTTP (80/tcp).\n'
  else
    log+=$'HTTP (80/tcp) not added.\n'
  fi
  if [[ $allow_https == 'yes' ]]; then
    nft add rule inet sentinelforge input tcp dport 443 ct state new accept >/dev/null 2>&1 || true
    log+=$'Allowed HTTPS (443/tcp).\n'
  else
    log+=$'HTTPS (443/tcp) not added.\n'
  fi
  SENTINELFORGE_FIREWALL_GUIDED_APPLIED=1
  SENTINELFORGE_FIREWALL_GUIDED_LOG="$log"
}

SentinelForge_firewall_guided_setup_iptables() {
  local ssh_port=$1
  if ! SentinelForge_ui_prompt_confirm "Proceed with iptables hardening?"; then
    SentinelForge_firewall_guided_cancel 'iptables guided setup aborted.'
    return 0
  fi
  local insert_established='no'
  local allow_http='no'
  local allow_https='no'
  local default_drop='no'
  while true; do
    local choice
    choice=$(SentinelForge_ui_display_menu 'iptables Guided Setup' \
      '1' "Insert ESTABLISHED/RELATED accept rule: $(SentinelForge_firewall_bool_label "$insert_established")" \
      '2' "Allow HTTP (80/tcp): $(SentinelForge_firewall_bool_label "$allow_http")" \
      '3' "Allow HTTPS (443/tcp): $(SentinelForge_firewall_bool_label "$allow_https")" \
      '4' "Set default INPUT policy to DROP: $(SentinelForge_firewall_bool_label "$default_drop")" \
      '5' 'Review & apply changes' \
      '6' 'Cancel')
    case "$choice" in
      1) insert_established=$(SentinelForge_firewall_bool_toggle "$insert_established") ;;
      2) allow_http=$(SentinelForge_firewall_bool_toggle "$allow_http") ;;
      3) allow_https=$(SentinelForge_firewall_bool_toggle "$allow_https") ;;
      4) default_drop=$(SentinelForge_firewall_bool_toggle "$default_drop") ;;
      5)
        local review
        printf -v review 'SSH port                 : %s\nESTABLISHED rule         : %s\nAllow HTTP (80/tcp)      : %s\nAllow HTTPS (443/tcp)    : %s\nDefault INPUT policy DROP: %s\n' \
          "$ssh_port" \
          "$(SentinelForge_firewall_bool_label "$insert_established")" \
          "$(SentinelForge_firewall_bool_label "$allow_http")" \
          "$(SentinelForge_firewall_bool_label "$allow_https")" \
          "$(SentinelForge_firewall_bool_label "$default_drop")"
        SentinelForge_ui_show_textbox 'Pending iptables changes' "$review" 20 78
        if SentinelForge_ui_prompt_confirm 'Apply these iptables changes now?' false; then
          break
        fi
        ;;
      6|'')
        SentinelForge_firewall_guided_cancel 'iptables guided setup cancelled.'
        return 0
        ;;
    esac
  done

  local log=''
  SentinelForge_firewall_ensure_port "$ssh_port"
  log+=$'Ensured SSH port allowed before applying rules.\n'
  if [[ $insert_established == 'yes' ]]; then
    iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
      iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    log+=$'Added ESTABLISHED/RELATED accept rule.\n'
  else
    log+=$'ESTABLISHED/RELATED rule unchanged.\n'
  fi
  if [[ $allow_http == 'yes' ]]; then
    iptables -I INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
    log+=$'Allowed HTTP (80/tcp).\n'
  else
    log+=$'HTTP (80/tcp) left unchanged.\n'
  fi
  if [[ $allow_https == 'yes' ]]; then
    iptables -I INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
    log+=$'Allowed HTTPS (443/tcp).\n'
  else
    log+=$'HTTPS (443/tcp) left unchanged.\n'
  fi
  if [[ $default_drop == 'yes' ]]; then
    iptables -P INPUT DROP
    log+=$'Default INPUT policy set to DROP.\n'
  else
    log+=$'Default INPUT policy unchanged.\n'
  fi
  SENTINELFORGE_FIREWALL_GUIDED_APPLIED=1
  SENTINELFORGE_FIREWALL_GUIDED_LOG="$log"
}

SentinelForge_firewall_apply_defaults() {
  SentinelForge_utils_require_root
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  local ssh_port=${SENTINELFORGE_STATE[ssh_port]:-$(SentinelForge_detect_current_ssh_port)}
  SENTINELFORGE_FIREWALL_GUIDED_APPLIED=0
  SENTINELFORGE_FIREWALL_GUIDED_LOG=''
  case "$backend" in
    ufw)
      SentinelForge_firewall_guided_setup_ufw "$ssh_port"
      ;;
    nftables)
      SentinelForge_firewall_guided_setup_nftables "$ssh_port"
      ;;
    iptables)
      SentinelForge_firewall_guided_setup_iptables "$ssh_port"
      ;;
    none)
      SENTINELFORGE_FIREWALL_GUIDED_LOG='No firewall backend detected. Install ufw, nftables, or iptables for hardened setup.'
      ;;
  esac
  if (( ${SENTINELFORGE_FIREWALL_GUIDED_APPLIED:-0} )); then
    if SentinelForge_ui_prompt_confirm "Enable SSH rate limiting for port ${ssh_port}?" false; then
      SentinelForge_firewall_apply_rate_limit
    fi
  fi
  if [[ -n ${SENTINELFORGE_FIREWALL_GUIDED_LOG:-} ]]; then
    SentinelForge_ui_show_textbox 'Firewall guided setup' "${SENTINELFORGE_FIREWALL_GUIDED_LOG}" 20 78
  fi
}

SentinelForge_firewall_apply_rate_limit() {
  SentinelForge_utils_require_root
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  local ssh_port=${SENTINELFORGE_STATE[ssh_port]:-$(SentinelForge_detect_current_ssh_port)}
  local message
  case "$backend" in
    ufw)
      if ufw status numbered 2>/dev/null | grep -F "${ssh_port}/tcp (limit)" >/dev/null; then
        message="UFW rate limiting already active for port ${ssh_port}."
      else
        ufw limit "${ssh_port}/tcp" >/dev/null 2>&1
        message="Applied UFW rate limit to port ${ssh_port}."
      fi
      ;;
    nftables)
      if ! nft list table inet sentinelforge >/dev/null 2>&1; then
        message='nftables rate limit requires the sentinelforge table. Run guided setup first.'
      elif nft list ruleset 2>/dev/null | grep -q "limit rate"; then
        message='nftables rate limit already configured for SSH.'
      else
        nft add rule inet sentinelforge input tcp dport ${ssh_port} ct state new limit rate 10/second burst 20 packets accept >/dev/null 2>&1 || true
        message='Added nftables rate limit (10/s burst 20) for SSH.'
      fi
      ;;
    iptables)
      if iptables -C INPUT -p tcp --dport "$ssh_port" -m connlimit --connlimit-above 10 -j REJECT 2>/dev/null; then
        message='iptables connlimit already protecting SSH.'
      else
        iptables -I INPUT -p tcp --dport "$ssh_port" -m connlimit --connlimit-above 10 -j REJECT
        message='Applied iptables connlimit (10 concurrent connections) to SSH.'
      fi
      ;;
    none)
      message='Install ufw, nftables, or iptables to use rate limiting.'
      ;;
  esac
  SentinelForge_ui_show_message 'Firewall' "${message:-Unable to apply rate limit.}"
}

SentinelForge_firewall_remove_rate_limit() {
  SentinelForge_utils_require_root
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-$(SentinelForge_detect_firewall_backend)}
  local ssh_port=${SENTINELFORGE_STATE[ssh_port]:-$(SentinelForge_detect_current_ssh_port)}
  case "$backend" in
    ufw)
      if ufw status numbered 2>/dev/null | grep -F "${ssh_port}/tcp (limit)" >/dev/null; then
        if SentinelForge_ui_prompt_confirm "Remove UFW rate limit for port ${ssh_port}?"; then
          ufw delete limit "${ssh_port}/tcp" >/dev/null 2>&1
          SentinelForge_ui_show_message 'Firewall' "Removed UFW rate limit for port ${ssh_port}."
        else
          SentinelForge_ui_show_message 'Firewall' 'Removal cancelled.'
        fi
      else
        SentinelForge_ui_show_message 'Firewall' "No UFW rate limit found for port ${ssh_port}."
      fi
      ;;
    nftables)
      if ! nft list table inet sentinelforge >/dev/null 2>&1; then
        SentinelForge_ui_show_message 'Firewall' 'Prepare nftables via firewall guided setup before removing rate limits.'
        return 0
      fi
      local handle
      handle=$(nft -a list chain inet sentinelforge input | awk '/limit rate/ {print $NF; exit}') || handle=""
      if [[ -n $handle ]]; then
        if SentinelForge_ui_prompt_confirm 'Remove nftables rate limit?'; then
          nft delete rule inet sentinelforge input handle "$handle" >/dev/null 2>&1 || true
          SentinelForge_ui_show_message 'Firewall' 'Removed nftables rate limit.'
        else
          SentinelForge_ui_show_message 'Firewall' 'Removal cancelled.'
        fi
      else
        SentinelForge_ui_show_message 'Firewall' 'No nftables rate limit found.'
      fi
      ;;
    iptables)
      if iptables -C INPUT -p tcp --dport "$ssh_port" -m connlimit --connlimit-above 10 -j REJECT 2>/dev/null; then
        if SentinelForge_ui_prompt_confirm 'Remove iptables connlimit rule for SSH?'; then
          iptables -D INPUT -p tcp --dport "$ssh_port" -m connlimit --connlimit-above 10 -j REJECT
          SentinelForge_ui_show_message 'Firewall' 'Removed iptables connlimit rule.'
        else
          SentinelForge_ui_show_message 'Firewall' 'Removal cancelled.'
        fi
      else
        SentinelForge_ui_show_message 'Firewall' 'No iptables connlimit rule found for SSH.'
      fi
      ;;
    none)
      SentinelForge_ui_show_message 'Firewall' 'Install ufw, nftables, or iptables to manage rate limiting.'
      ;;
  esac
}

SentinelForge_firewall_show_status_panel() {
  SentinelForge_firewall_refresh_state
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-none}
  local summary
  printf -v summary 'Backend: %s\nEnabled: %s\nDefault incoming: %s\nSSH allowed: %s\nSSH rate limit: %s\n' \
    "$backend" \
    "${SENTINELFORGE_STATE[firewall_enabled]}" \
    "${SENTINELFORGE_STATE[firewall_default_in]}" \
    "${SENTINELFORGE_STATE[firewall_ssh_allowed]}" \
    "${SENTINELFORGE_STATE[ssh_rate_limit]}"
  local details
  case "$backend" in
    ufw)
      details=$(ufw status verbose 2>/dev/null || echo 'ufw status unavailable')
      ;;
    nftables)
      details=$(nft list ruleset 2>/dev/null || echo 'nft list ruleset unavailable')
      ;;
    iptables)
      details=$(iptables -S 2>/dev/null || echo 'iptables -S unavailable')
      ;;
    none)
      details='No firewall backend detected.'
      ;;
  esac
  summary+=$'\n----\n'
  summary+="$details\n"
  SentinelForge_ui_show_textbox 'Firewall status' "$summary" 22 78
}

SentinelForge_firewall_allowlist_add() {
  SentinelForge_utils_require_root
  SentinelForge_firewall_refresh_state
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-none}
  local ssh_port=${SENTINELFORGE_STATE[ssh_port]:-22}
  local entry
  entry=$(SentinelForge_ui_prompt_input 'Enter IP or CIDR to allow: ')
  if [[ ${SENTINELFORGE_UI_LAST_STATUS:-ok} != 'ok' ]]; then
    return 0
  fi
  [[ -z "$entry" ]] && return 0
  case "$backend" in
    ufw)
      ufw allow from "$entry" to any port "$ssh_port" proto tcp >/dev/null 2>&1
      SentinelForge_ui_show_message 'Firewall' "Allow rule added for ${entry} -> port ${ssh_port}."
      ;;
    iptables)
      iptables -I INPUT -p tcp --dport "$ssh_port" -s "$entry" -m state --state NEW -j ACCEPT
      SentinelForge_ui_show_message 'Firewall' "iptables allow rule added for ${entry}."
      ;;
    nftables)
      SentinelForge_ui_show_message 'Firewall' 'Add allow entries manually via nft commands (not yet automated).'
      ;;
    none)
      SentinelForge_ui_show_message 'Firewall' 'No firewall backend detected.'
      ;;
  esac
}

SentinelForge_firewall_allowlist_remove() {
  SentinelForge_utils_require_root
  SentinelForge_firewall_refresh_state
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-none}
  local ssh_port=${SENTINELFORGE_STATE[ssh_port]:-22}
  case "$backend" in
    ufw)
      local rules
      rules=$(ufw status numbered 2>/dev/null | sed 's/^/ /')
      SentinelForge_ui_show_textbox 'Current UFW rules' "${rules:-No UFW rules}" 22 78
      local rule
      rule=$(SentinelForge_ui_prompt_input 'Enter rule number to delete: ')
      if [[ ${SENTINELFORGE_UI_LAST_STATUS:-ok} != 'ok' ]]; then
        return 0
      fi
      [[ -z "$rule" ]] && return 0
      if ufw delete "$rule" >/dev/null 2>&1; then
        SentinelForge_ui_show_message 'Firewall' "Removed UFW rule ${rule}."
      else
        SentinelForge_ui_show_message 'Firewall' "Failed to remove UFW rule ${rule}."
      fi
      ;;
    iptables)
      local entry
      entry=$(SentinelForge_ui_prompt_input 'Enter IP/CIDR to remove: ')
      if [[ ${SENTINELFORGE_UI_LAST_STATUS:-ok} != 'ok' ]]; then
        return 0
      fi
      [[ -z "$entry" ]] && return 0
      if iptables -D INPUT -p tcp --dport "$ssh_port" -s "$entry" -m state --state NEW -j ACCEPT 2>/dev/null; then
        SentinelForge_ui_show_message 'Firewall' "Removed iptables allow rule for ${entry}."
      else
        SentinelForge_ui_show_message 'Firewall' "No matching iptables rule for ${entry}."
      fi
      ;;
    nftables)
      SentinelForge_ui_show_message 'Firewall' 'Remove allow entries manually via nft commands (not yet automated).'
      ;;
    none)
      SentinelForge_ui_show_message 'Firewall' 'No firewall backend detected.'
      ;;
  esac
}

SentinelForge_firewall_show_allow_blocked() {
  SentinelForge_firewall_refresh_state
  local backend=${SENTINELFORGE_STATE[firewall_backend]:-none}
  local allowed=''
  local blocked=''
  case "$backend" in
    ufw)
      allowed=$(ufw status numbered 2>/dev/null | awk '/ALLOW/ {print}')
      blocked=$(ufw status numbered 2>/dev/null | awk '/(DENY|REJECT)/ {print}')
      ;;
    iptables)
      allowed=$(iptables -S INPUT 2>/dev/null | grep -E 'ACCEPT' || true)
      blocked=$(iptables -S INPUT 2>/dev/null | grep -E 'DROP|REJECT' || true)
      ;;
    nftables)
      allowed=$(nft list ruleset 2>/dev/null | grep -i 'accept' || true)
      blocked=$(nft list ruleset 2>/dev/null | grep -i 'drop\|reject' || true)
      ;;
    none)
      allowed='No firewall backend detected.'
      blocked='No firewall backend detected.'
      ;;
  esac
  [[ -z $allowed ]] && allowed='(none)'
  [[ -z $blocked ]] && blocked='(none)'
  local content
  printf -v content 'Allowed entries:\n%s\n\nBlocked entries:\n%s\n' "$allowed" "$blocked"
  SentinelForge_ui_show_textbox 'Allowed & Blocked entries' "$content" 22 78
}
