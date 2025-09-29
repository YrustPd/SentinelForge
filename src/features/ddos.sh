#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SENTINELFORGE_DDOS_CHAIN='SF_DDOS_GUARD'
SENTINELFORGE_DDOS_LOG_CHAIN='SF_DDOS_LOG'
SENTINELFORGE_DDOS_IPSET='sentinelforge_ddos_block'
SENTINELFORGE_DDOS_TABLE='sentinelforge_ddos'
SENTINELFORGE_DDOS_SET_V4='blocklist4'
SENTINELFORGE_DDOS_SET_V6='blocklist6'
SENTINELFORGE_DDOS_SYSCTL_PROFILE='/etc/sysctl.d/99-sentinelforge-ddos.conf'
SENTINELFORGE_DDOS_NGINX_DIR='/etc/nginx/sentinelforge'
SENTINELFORGE_DDOS_NGINX_SCRIPT="${SENTINELFORGE_DDOS_NGINX_DIR}/anti_ddos_challenge.lua"
SENTINELFORGE_DDOS_NGINX_SNIPPET="${SENTINELFORGE_DDOS_NGINX_DIR}/sentinelforge-ddos-snippet.conf"
SENTINELFORGE_DDOS_NGINX_README="${SENTINELFORGE_DDOS_NGINX_DIR}/README.txt"

SentinelForge_ddos_refresh_state() {
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  SENTINELFORGE_STATE[ddos_backend]="$backend"
  SENTINELFORGE_STATE[ddos_guard]='disabled'
  SENTINELFORGE_STATE[ddos_guard_hook]='no'
  SENTINELFORGE_STATE[ddos_blocklist]='0 entries'
  SENTINELFORGE_STATE[ddos_sysctl]='no'
  SENTINELFORGE_STATE[ddos_notes]=''

  case "$backend" in
    ufw|iptables)
      if iptables -w -nL "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
        SENTINELFORGE_STATE[ddos_guard]='enabled'
        if iptables -w -C INPUT -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
          SENTINELFORGE_STATE[ddos_guard_hook]='yes'
        fi
      fi
      if command -v ipset >/dev/null 2>&1 && ipset list "$SENTINELFORGE_DDOS_IPSET" >/dev/null 2>&1; then
        local entries
        entries=$(ipset list "$SENTINELFORGE_DDOS_IPSET" 2>/dev/null | awk '/Number of entries/ {print $4; exit}')
        SENTINELFORGE_STATE[ddos_blocklist]="${entries:-0} entries"
      elif ! command -v ipset >/dev/null 2>&1; then
        SENTINELFORGE_STATE[ddos_notes]+=$'ipset utility missing; blocklist persistence limited.\n'
      fi
      ;;
    nftables)
      if nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1; then
        SENTINELFORGE_STATE[ddos_guard]='enabled'
        if nft list chain inet "$SENTINELFORGE_DDOS_TABLE" guard >/dev/null 2>&1; then
          SENTINELFORGE_STATE[ddos_guard_hook]='yes'
        fi
        local v4_entries v6_entries
        v4_entries=$(nft list set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V4" 2>/dev/null | awk '/elements =/ {gsub(/[^0-9]/, "", $0); print $0; exit}')
        v6_entries=$(nft list set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V6" 2>/dev/null | awk '/elements =/ {gsub(/[^0-9]/, "", $0); print $0; exit}')
        local total=$(( ${v4_entries:-0} + ${v6_entries:-0} ))
        SENTINELFORGE_STATE[ddos_blocklist]="${total} entries"
      fi
      ;;
    none)
      SENTINELFORGE_STATE[ddos_notes]='No firewall backend detected; DDoS guard unavailable.'
      ;;
  esac

  if [[ -f "$SENTINELFORGE_DDOS_SYSCTL_PROFILE" ]]; then
    SENTINELFORGE_STATE[ddos_sysctl]='yes'
  fi

  local talkers
  talkers=$(SentinelForge_detect_top_remote_ips)
  if [[ -n "$talkers" ]]; then
    SENTINELFORGE_STATE[ddos_top_talkers]="$talkers"
  else
    SENTINELFORGE_STATE[ddos_top_talkers]='(no established TCP peers)'
  fi

  local nginx_script="$SENTINELFORGE_DDOS_NGINX_SCRIPT"
  local nginx_snippet="$SENTINELFORGE_DDOS_NGINX_SNIPPET"
  if [[ -f "$nginx_script" && -f "$nginx_snippet" ]]; then
    SENTINELFORGE_STATE[ddos_nginx]='installed'
  elif [[ -f "$nginx_script" || -f "$nginx_snippet" ]]; then
    SENTINELFORGE_STATE[ddos_nginx]='partial'
  else
    SENTINELFORGE_STATE[ddos_nginx]='missing'
  fi
}

SentinelForge_ddos_show_overview() {
  SentinelForge_ddos_refresh_state
  local backend=${SENTINELFORGE_STATE[ddos_backend]}
  local guard=${SENTINELFORGE_STATE[ddos_guard]}
  local hook=${SENTINELFORGE_STATE[ddos_guard_hook]}
  local blocklist=${SENTINELFORGE_STATE[ddos_blocklist]}
  local sysctl=${SENTINELFORGE_STATE[ddos_sysctl]}
  local nginx=${SENTINELFORGE_STATE[ddos_nginx]:-missing}
  local notes=${SENTINELFORGE_STATE[ddos_notes]}
  local talkers=${SENTINELFORGE_STATE[ddos_top_talkers]}
  local summary
  printf -v summary 'Backend           : %s\nGuard chain       : %s (hooked: %s)\nBlocklist entries : %s\nKernel DDOS tune  : %s\nNginx challenge   : %s\n\nTop talkers:\n%s\n' \
    "$backend" "$guard" "$hook" "$blocklist" "$sysctl" "$nginx" "${talkers//$'\n'/\\n}"
  if [[ -n "$notes" ]]; then
    summary+=$'\nNotes:\n'
    summary+="$notes"
  fi
  SentinelForge_ui_show_textbox 'DDoS protection status' "$summary" 22 80
}

SentinelForge_ddos_ensure_ipset() {
  if ! command -v ipset >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'DDoS guard' 'ipset utility not installed. Install ipset for efficient blocklists.'
    return 1
  fi
  if ! ipset list "$SENTINELFORGE_DDOS_IPSET" >/dev/null 2>&1; then
    ipset create "$SENTINELFORGE_DDOS_IPSET" hash:ip timeout 86400 comment -exist
  fi
}

SentinelForge_ddos_apply_guard_iptables() {
  SentinelForge_utils_require_root
  SentinelForge_ddos_ensure_ipset || true

  if ! iptables -w -nL "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
    iptables -w -N "$SENTINELFORGE_DDOS_CHAIN"
  fi
  iptables -w -F "$SENTINELFORGE_DDOS_CHAIN"

  if ! iptables -w -nL "$SENTINELFORGE_DDOS_LOG_CHAIN" >/dev/null 2>&1; then
    iptables -w -N "$SENTINELFORGE_DDOS_LOG_CHAIN"
  fi
  iptables -w -F "$SENTINELFORGE_DDOS_LOG_CHAIN"
  iptables -w -A "$SENTINELFORGE_DDOS_LOG_CHAIN" -m limit --limit 6/min --limit-burst 24 -j LOG --log-prefix 'SF-DDOS ' --log-level 4
  iptables -w -A "$SENTINELFORGE_DDOS_LOG_CHAIN" -j DROP

  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -m conntrack --ctstate INVALID -j "$SENTINELFORGE_DDOS_LOG_CHAIN"
  if command -v ipset >/dev/null 2>&1 && ipset list "$SENTINELFORGE_DDOS_IPSET" >/dev/null 2>&1; then
    iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -m set --match-set "$SENTINELFORGE_DDOS_IPSET" src -j "$SENTINELFORGE_DDOS_LOG_CHAIN"
  fi
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -p tcp --syn -m hashlimit --hashlimit-name sf-syn \
    --hashlimit-above 40/second --hashlimit-burst 80 --hashlimit-mode srcip -j "$SENTINELFORGE_DDOS_LOG_CHAIN"
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -p tcp --syn -m connlimit --connlimit-above 120 --connlimit-mask 32 -j "$SENTINELFORGE_DDOS_LOG_CHAIN"
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -p udp -m hashlimit --hashlimit-name sf-udp \
    --hashlimit-above 400/second --hashlimit-burst 800 --hashlimit-mode srcip -j "$SENTINELFORGE_DDOS_LOG_CHAIN"
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -p icmp -m limit --limit 6/second --limit-burst 12 -j RETURN
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -p icmp -j "$SENTINELFORGE_DDOS_LOG_CHAIN"
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -m limit --limit 120/second --limit-burst 240 -j RETURN
  iptables -w -A "$SENTINELFORGE_DDOS_CHAIN" -j "$SENTINELFORGE_DDOS_LOG_CHAIN"

  if ! iptables -w -C INPUT -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
    iptables -w -I INPUT 1 -j "$SENTINELFORGE_DDOS_CHAIN"
  fi
  if ! iptables -w -C FORWARD -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
    iptables -w -I FORWARD 1 -j "$SENTINELFORGE_DDOS_CHAIN" 2>/dev/null || true
  fi
  SentinelForge_ui_show_message 'DDoS guard' "Applied iptables guard chain ${SENTINELFORGE_DDOS_CHAIN}."
}

SentinelForge_ddos_remove_guard_iptables() {
  SentinelForge_utils_require_root
  if iptables -w -C INPUT -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
    iptables -w -D INPUT -j "$SENTINELFORGE_DDOS_CHAIN"
  fi
  if iptables -w -C FORWARD -j "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
    iptables -w -D FORWARD -j "$SENTINELFORGE_DDOS_CHAIN" 2>/dev/null || true
  fi
  if iptables -w -nL "$SENTINELFORGE_DDOS_CHAIN" >/dev/null 2>&1; then
    iptables -w -F "$SENTINELFORGE_DDOS_CHAIN"
    iptables -w -X "$SENTINELFORGE_DDOS_CHAIN"
  fi
  if iptables -w -nL "$SENTINELFORGE_DDOS_LOG_CHAIN" >/dev/null 2>&1; then
    iptables -w -F "$SENTINELFORGE_DDOS_LOG_CHAIN"
    iptables -w -X "$SENTINELFORGE_DDOS_LOG_CHAIN"
  fi
  SentinelForge_ui_show_message 'DDoS guard' "Removed iptables guard chain ${SENTINELFORGE_DDOS_CHAIN}."
}

SentinelForge_ddos_apply_guard_nft() {
  SentinelForge_utils_require_root
  nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1 || nft add table inet "$SENTINELFORGE_DDOS_TABLE"

  if ! nft list set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V4" >/dev/null 2>&1; then
    nft add set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V4" '{ type ipv4_addr; timeout 1d; }'
  fi
  if ! nft list set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V6" >/dev/null 2>&1; then
    nft add set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V6" '{ type ipv6_addr; timeout 1d; }'
  fi

  nft delete chain inet "$SENTINELFORGE_DDOS_TABLE" guard >/dev/null 2>&1 || true
  nft add chain inet "$SENTINELFORGE_DDOS_TABLE" guard '{ type filter hook input priority -160; policy accept; }'

  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard ct state { established, related } return
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard ct state invalid limit rate 10/second log prefix "SF-DDOS INVALID " level warning drop
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard ip saddr @${SENTINELFORGE_DDOS_SET_V4} log prefix "SF-DDOS BLOCK " level warning drop
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard ip6 saddr @${SENTINELFORGE_DDOS_SET_V6} log prefix "SF-DDOS BLOCK6 " level warning drop
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard tcp flags syn new meter sf_syn { ip saddr limit rate over 40/second } log prefix "SF-DDOS SYN " level warning drop
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard udp meter sf_udp { ip saddr limit rate over 400/second } log prefix "SF-DDOS UDP " level warning drop
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard icmp type echo-request limit rate over 6/second log prefix "SF-DDOS ICMP " level warning drop
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard icmpv6 type echo-request limit rate over 6/second log prefix "SF-DDOS ICMP6 " level warning drop
  nft add rule inet "$SENTINELFORGE_DDOS_TABLE" guard counter return

  SentinelForge_ui_show_message 'DDoS guard' "Applied nftables table ${SENTINELFORGE_DDOS_TABLE}."
}

SentinelForge_ddos_remove_guard_nft() {
  SentinelForge_utils_require_root
  if nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1; then
    nft delete table inet "$SENTINELFORGE_DDOS_TABLE"
  fi
  SentinelForge_ui_show_message 'DDoS guard' "Removed nftables table ${SENTINELFORGE_DDOS_TABLE}."
}

SentinelForge_ddos_apply_guard() {
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  case "$backend" in
    ufw|iptables)
      SentinelForge_ddos_apply_guard_iptables
      ;;
    nftables)
      SentinelForge_ddos_apply_guard_nft
      ;;
    none)
      SentinelForge_ui_show_message 'DDoS guard' 'No firewall backend detected. Configure firewall before enabling guard.'
      return 1
      ;;
  esac
}

SentinelForge_ddos_remove_guard() {
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  case "$backend" in
    ufw|iptables)
      SentinelForge_ddos_remove_guard_iptables
      ;;
    nftables)
      SentinelForge_ddos_remove_guard_nft
      ;;
    none)
      SentinelForge_ui_show_message 'DDoS guard' 'No guard to remove.'
      ;;
  esac
}

SentinelForge_ddos_kernel_profile_content() {
  cat <<'CONF'
# Managed by SentinelForge — DDoS hardening extras
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 4096
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 900
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_ratelimit = 100
net.ipv4.icmp_ratemask = 88089
CONF
}

SentinelForge_ddos_apply_kernel_profile() {
  SentinelForge_utils_require_root
  local summary
  summary=$(SentinelForge_ddos_kernel_profile_content)
  SentinelForge_ui_show_textbox 'Kernel hardening' "The following values will be written to ${SENTINELFORGE_DDOS_SYSCTL_PROFILE}:\n\n${summary}" 24 80
  if ! SentinelForge_ui_prompt_confirm 'Apply DDoS kernel profile via sysctl?'; then
    SentinelForge_ui_show_message 'DDoS guard' 'No kernel changes applied.'
    return 0
  fi
  if [[ -f "$SENTINELFORGE_DDOS_SYSCTL_PROFILE" ]]; then
    SentinelForge_utils_backup_file "$SENTINELFORGE_DDOS_SYSCTL_PROFILE" 'sysctl --system' >/dev/null || true
  fi
  { echo '# SentinelForge DDoS profile'; SentinelForge_ddos_kernel_profile_content; } >"$SENTINELFORGE_DDOS_SYSCTL_PROFILE"
  if sysctl --system >/dev/null 2>&1; then
    SentinelForge_ui_show_message 'DDoS guard' 'Kernel hardening profile applied.'
  else
    rm -f "$SENTINELFORGE_DDOS_SYSCTL_PROFILE"
    SentinelForge_ui_show_message 'DDoS guard' 'Failed to reload sysctl. Profile removed.'
    return 1
  fi
}

SentinelForge_ddos_remove_kernel_profile() {
  SentinelForge_utils_require_root
  if [[ ! -f "$SENTINELFORGE_DDOS_SYSCTL_PROFILE" ]]; then
    SentinelForge_ui_show_message 'DDoS guard' 'Kernel DDoS profile is not present.'
    return 0
  fi
  SentinelForge_utils_backup_file "$SENTINELFORGE_DDOS_SYSCTL_PROFILE" 'sysctl --system' >/dev/null || true
  rm -f "$SENTINELFORGE_DDOS_SYSCTL_PROFILE"
  sysctl --system >/dev/null 2>&1 || true
  SentinelForge_ui_show_message 'DDoS guard' 'Kernel DDoS profile removed.'
}

SentinelForge_ddos_is_ipv6() {
  local ip=$1
  [[ "$ip" == *:* ]]
}

SentinelForge_ddos_block_ip() {
  SentinelForge_utils_require_root
  local ip=$1 timeout=${2:-3600}
  if [[ -z "$ip" ]]; then
    SentinelForge_ui_show_message 'DDoS guard' 'No IP specified.'
    return 1
  fi
  if ! [[ "$timeout" =~ ^[0-9]+$ ]]; then
    timeout=3600
  fi
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  case "$backend" in
    ufw|iptables)
      SentinelForge_ddos_ensure_ipset || return 1
      if SentinelForge_ddos_is_ipv6 "$ip"; then
        SentinelForge_ui_show_message 'DDoS guard' 'IPv6 blocklist via ipset is not configured; enable nftables backend for IPv6 addresses.'
        return 1
      fi
      ipset add "$SENTINELFORGE_DDOS_IPSET" "$ip" timeout "$timeout" -exist
      SentinelForge_ui_show_message 'DDoS guard' "Added ${ip} to ipset (${timeout}s)."
      ;;
    nftables)
      if ! nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1; then
        SentinelForge_ddos_apply_guard_nft
      fi
      if SentinelForge_ddos_is_ipv6 "$ip"; then
        nft add element inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V6" "{ $ip timeout ${timeout}s }"
      else
        nft add element inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V4" "{ $ip timeout ${timeout}s }"
      fi
      SentinelForge_ui_show_message 'DDoS guard' "Added ${ip} to nftables blocklist (${timeout}s)."
      ;;
    none)
      SentinelForge_ui_show_message 'DDoS guard' 'No firewall backend loaded. Cannot block IP.'
      return 1
      ;;
  esac
}

SentinelForge_ddos_unblock_ip() {
  SentinelForge_utils_require_root
  local ip=$1
  if [[ -z "$ip" ]]; then
    SentinelForge_ui_show_message 'DDoS guard' 'No IP specified.'
    return 1
  fi
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  case "$backend" in
    ufw|iptables)
      if command -v ipset >/dev/null 2>&1 && ipset list "$SENTINELFORGE_DDOS_IPSET" >/dev/null 2>&1; then
        ipset del "$SENTINELFORGE_DDOS_IPSET" "$ip" 2>/dev/null || true
      fi
      ;;
    nftables)
      if nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1; then
        if SentinelForge_ddos_is_ipv6 "$ip"; then
          nft delete element inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V6" "{ $ip }" 2>/dev/null || true
        else
          nft delete element inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V4" "{ $ip }" 2>/dev/null || true
        fi
      fi
      ;;
  esac
  SentinelForge_ui_show_message 'DDoS guard' "Removed ${ip} from SentinelForge blocklist."
}

SentinelForge_ddos_format_ipset_members() {
  local name=$1
  if ! ipset list "$name" >/dev/null 2>&1; then
    return 1
  fi
  ipset list "$name" | awk '
    /^Members:/ {members=1; next}
    members && NF {gsub(/^[[:space:]]+/, ""); print $0}
  '
}

SentinelForge_ddos_list_blocked() {
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  local content=''
  case "$backend" in
    ufw|iptables)
      if command -v ipset >/dev/null 2>&1 && ipset list "$SENTINELFORGE_DDOS_IPSET" >/dev/null 2>&1; then
        local members
        members=$(SentinelForge_ddos_format_ipset_members "$SENTINELFORGE_DDOS_IPSET" || true)
        if [[ -n $members ]]; then
          content=$"Active entries (${SENTINELFORGE_DDOS_IPSET}):\n\n${members}"
        else
          content=$"No entries currently stored in ${SENTINELFORGE_DDOS_IPSET}."
        fi
      else
        content='ipset not available or blocklist empty.'
      fi
      ;;
    nftables)
      if nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1; then
        local v4 v6
        v4=$(nft -a list set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V4" 2>/dev/null | awk '/elements =/ {gsub(/.*= \{/,""); gsub(/\}.*/,""); gsub(/,/ ,"\n"); print}' || true)
        v6=$(nft -a list set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V6" 2>/dev/null | awk '/elements =/ {gsub(/.*= \{/,""); gsub(/\}.*/,""); gsub(/,/ ,"\n"); print}' || true)
        [[ -z $v4 ]] && v4='(no IPv4 entries)'
        [[ -z $v6 ]] && v6='(no IPv6 entries)'
        content=$"IPv4 entries (${SENTINELFORGE_DDOS_SET_V4}):\n${v4}\n\nIPv6 entries (${SENTINELFORGE_DDOS_SET_V6}):\n${v6}"
      else
        content='nftables guard not applied yet.'
      fi
      ;;
    none)
      content='No firewall backend detected.'
      ;;
  esac
  SentinelForge_ui_show_textbox 'Blocked sources' "$content" 24 80
}

SentinelForge_ddos_clear_blocklist() {
  SentinelForge_utils_require_root
  local backend
  backend=$(SentinelForge_detect_firewall_backend)
  case "$backend" in
    ufw|iptables)
      if command -v ipset >/dev/null 2>&1 && ipset list "$SENTINELFORGE_DDOS_IPSET" >/dev/null 2>&1; then
        ipset flush "$SENTINELFORGE_DDOS_IPSET"
        SentinelForge_ui_show_message 'DDoS guard' 'Cleared ipset blocklist.'
      else
        SentinelForge_ui_show_message 'DDoS guard' 'No ipset blocklist present.'
      fi
      ;;
    nftables)
      if nft list table inet "$SENTINELFORGE_DDOS_TABLE" >/dev/null 2>&1; then
        nft flush set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V4" 2>/dev/null || true
        nft flush set inet "$SENTINELFORGE_DDOS_TABLE" "$SENTINELFORGE_DDOS_SET_V6" 2>/dev/null || true
        SentinelForge_ui_show_message 'DDoS guard' 'Cleared nftables blocklists.'
      else
        SentinelForge_ui_show_message 'DDoS guard' 'No nftables guard present.'
      fi
      ;;
    none)
      SentinelForge_ui_show_message 'DDoS guard' 'No firewall backend detected.'
      ;;
  esac
}

SentinelForge_ddos_prompt_block_ip() {
  local ip timeout
  ip=$(SentinelForge_ui_prompt_input 'Enter IP to block (IPv4 or IPv6): ')
  if [[ ${SENTINELFORGE_UI_LAST_STATUS:-ok} == 'cancel' ]]; then
    return 0
  fi
  timeout=$(SentinelForge_ui_prompt_input 'Block duration in seconds (default 3600): ' '3600')
  if [[ ${SENTINELFORGE_UI_LAST_STATUS:-ok} == 'cancel' ]]; then
    return 0
  fi
  SentinelForge_ddos_block_ip "$ip" "$timeout"
}

SentinelForge_ddos_prompt_unblock_ip() {
  local ip
  ip=$(SentinelForge_ui_prompt_input 'Enter IP to remove from blocklist: ')
  if [[ ${SENTINELFORGE_UI_LAST_STATUS:-ok} == 'cancel' ]]; then
    return 0
  fi
  SentinelForge_ddos_unblock_ip "$ip"
}

SentinelForge_ddos_view_top_talkers() {
  local talkers
  talkers=$(SentinelForge_detect_top_remote_ips)
  if [[ -z "$talkers" ]]; then
    talkers='No established TCP peers detected.'
  fi
  SentinelForge_ui_show_textbox 'Top remote peers' "$talkers" 20 70
}

SentinelForge_ddos_gatekeeper_readiness() {
  local report='Gatekeeper readiness checks:\n'
  if [[ -c /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages ]]; then
    local hp
    hp=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || echo '0')
    report+=$"- Hugepages (2MB) configured : ${hp}\n"
    if (( hp < 256 )); then
      report+=$'- Recommendation           : echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages\n'
    fi
  else
    report+=$'- Hugepages path missing (skip).\n'
  fi

  if lsmod | grep -q '^vfio_pci'; then
    report+=$'- vfio-pci module          : loaded\n'
  else
    report+=$'- vfio-pci module          : not loaded (run: sudo modprobe vfio-pci)\n'
  fi

  if grep -q '^intel_iommu=on' /proc/cmdline 2>/dev/null; then
    report+=$'- intel_iommu kernel flag  : enabled\n'
  else
    report+=$'- intel_iommu kernel flag  : missing (add intel_iommu=on to GRUB)\n'
  fi

  if [[ -d /sys/kernel/iommu_groups ]]; then
    if [[ -n $(ls /sys/kernel/iommu_groups 2>/dev/null) ]]; then
      report+=$'- IOMMU groups             : detected\n'
    else
      report+=$'- IOMMU groups             : none visible\n'
    fi
  else
    report+=$'- IOMMU groups             : path absent\n'
  fi

  report+=$'\nFollow Gatekeeper setup instructions for full deployment (DPDK, BIRD, LuaJIT).'
  SentinelForge_ui_show_textbox 'Gatekeeper readiness' "$report" 22 78
}

SentinelForge_ddos_nginx_status_summary() {
  local script_status='missing'
  local snippet_status='missing'
  if [[ -f "$SENTINELFORGE_DDOS_NGINX_SCRIPT" ]]; then
    script_status='present'
  fi
  if [[ -f "$SENTINELFORGE_DDOS_NGINX_SNIPPET" ]]; then
    snippet_status='present'
  fi
  printf 'Lua script: %s\nSnippet   : %s\nInstall dir: %s\n' \
    "$script_status" "$snippet_status" "$SENTINELFORGE_DDOS_NGINX_DIR"
}

SentinelForge_ddos_nginx_install_assets() {
  SentinelForge_utils_require_root
  local template_script="${SENTINELFORGE_SHARE_ROOT}/templates/nginx-anti-ddos-challenge.lua"
  local template_snippet="${SENTINELFORGE_SHARE_ROOT}/templates/nginx-anti-ddos-snippet.conf"
  if [[ ! -f "$template_script" ]]; then
    SentinelForge_ui_show_message 'DDoS guard' 'Template for Nginx Lua challenge is missing.'
    return 1
  fi
  SentinelForge_utils_info "Installing nginx Lua challenge assets into ${SENTINELFORGE_DDOS_NGINX_DIR}"
  mkdir -p "$SENTINELFORGE_DDOS_NGINX_DIR"

  if command -v install >/dev/null 2>&1; then
    if ! install -m 0644 "$template_script" "$SENTINELFORGE_DDOS_NGINX_SCRIPT"; then
      SentinelForge_utils_warn "install command failed for ${SENTINELFORGE_DDOS_NGINX_SCRIPT}; falling back to cp"
      cp "$template_script" "$SENTINELFORGE_DDOS_NGINX_SCRIPT"
      chmod 0644 "$SENTINELFORGE_DDOS_NGINX_SCRIPT"
    fi
    if [[ -f "$template_snippet" ]]; then
      if ! install -m 0644 "$template_snippet" "$SENTINELFORGE_DDOS_NGINX_SNIPPET"; then
        SentinelForge_utils_warn "install command failed for ${SENTINELFORGE_DDOS_NGINX_SNIPPET}; falling back to cp"
        cp "$template_snippet" "$SENTINELFORGE_DDOS_NGINX_SNIPPET"
        chmod 0644 "$SENTINELFORGE_DDOS_NGINX_SNIPPET"
      fi
    fi
  else
    cp "$template_script" "$SENTINELFORGE_DDOS_NGINX_SCRIPT"
    chmod 0644 "$SENTINELFORGE_DDOS_NGINX_SCRIPT"
    if [[ -f "$template_snippet" ]]; then
      cp "$template_snippet" "$SENTINELFORGE_DDOS_NGINX_SNIPPET"
      chmod 0644 "$SENTINELFORGE_DDOS_NGINX_SNIPPET"
    fi
  fi

  if ! cat <<EOF >"$SENTINELFORGE_DDOS_NGINX_README"; then
SentinelForge — Nginx/OpenResty Anti-DDoS integration

1. Ensure lua-nginx-module support is available (nginx-extras, openresty, or similar).
2. Inside the http { } block of nginx.conf include the shared dict snippet:
     include ${SENTINELFORGE_DDOS_NGINX_SNIPPET};
3. Inside each server/location you wish to protect add:
     access_by_lua_file ${SENTINELFORGE_DDOS_NGINX_SCRIPT};
4. Reload nginx after testing the configuration with "nginx -t" (or "openresty -t").

The Lua challenge script originates from https://github.com/C0nw0nk/Nginx-Lua-Anti-DDoS (MIT). SentinelForge copies it verbatim for local use.
EOF
    SentinelForge_ui_show_message 'DDoS guard' 'Failed to write nginx integration README. Check permissions.'
    return 1
  fi

  SentinelForge_utils_info "Nginx Lua challenge assets installed successfully"
  SentinelForge_ui_show_message 'DDoS guard' 'Installed Lua challenge and snippet under /etc/nginx/sentinelforge/. Remember to include them in nginx.conf.'
}

SentinelForge_ddos_nginx_remove_assets() {
  SentinelForge_utils_require_root
  rm -f "$SENTINELFORGE_DDOS_NGINX_SCRIPT" "$SENTINELFORGE_DDOS_NGINX_SNIPPET" "$SENTINELFORGE_DDOS_NGINX_README"
  if [[ -d "$SENTINELFORGE_DDOS_NGINX_DIR" && -z $(ls -A "$SENTINELFORGE_DDOS_NGINX_DIR" 2>/dev/null) ]]; then
    rmdir "$SENTINELFORGE_DDOS_NGINX_DIR" 2>/dev/null || true
  fi
  SentinelForge_ui_show_message 'DDoS guard' 'Removed SentinelForge Nginx assets.'
}

SentinelForge_ddos_nginx_show_instructions() {
  local status
  status=$(SentinelForge_ddos_nginx_status_summary)
  local binary='(nginx not detected)'
  if command -v nginx >/dev/null 2>&1; then
    binary=$(command -v nginx)
  elif command -v openresty >/dev/null 2>&1; then
    binary=$(command -v openresty)
  fi
  local guidance
  printf -v guidance 'Status:\n%s\n\nLua script path : %s\nSnippet path    : %s\nExecutable      : %s\n\nSteps:\n 1. Copy shared dict directives into http { } (see snippet).\n 2. Add access_by_lua_file inside server/location blocks.\n 3. Reload nginx after testing with "%s -t".\n\nTip: ensure lua_package_path includes the SentinelForge directory if customised.\n' \
    "$status" "$SENTINELFORGE_DDOS_NGINX_SCRIPT" "$SENTINELFORGE_DDOS_NGINX_SNIPPET" "$binary" "$binary"
  SentinelForge_ui_show_textbox 'Nginx/OpenResty integration' "$guidance" 24 82
}

SentinelForge_ddos_nginx_test_config() {
  SentinelForge_utils_require_root
  local binary
  if command -v nginx >/dev/null 2>&1; then
    binary=$(command -v nginx)
  elif command -v openresty >/dev/null 2>&1; then
    binary=$(command -v openresty)
  else
    SentinelForge_ui_show_message 'DDoS guard' 'Neither nginx nor openresty binary detected in PATH.'
    return 1
  fi
  local output status
  local restore_errexit=0
  if [[ $- == *e* ]]; then
    restore_errexit=1
    set +e
  fi
  output=$("$binary" -t 2>&1)
  status=$?
  if (( restore_errexit )); then
    set -e
  fi
  if (( status == 0 )); then
    SentinelForge_ui_show_textbox 'Nginx config test' "$output" 20 78
    return 0
  fi
  SentinelForge_utils_warn "nginx/openresty config test failed with exit ${status}: ${output}"
  SentinelForge_ui_show_textbox 'Nginx config test (failed)' "$output" 20 78
  return "$status"
}

SentinelForge_ddos_nginx_menu() {
  while true; do
    local script_status='missing'
    local snippet_status='missing'
    [[ -f "$SENTINELFORGE_DDOS_NGINX_SCRIPT" ]] && script_status='present'
    [[ -f "$SENTINELFORGE_DDOS_NGINX_SNIPPET" ]] && snippet_status='present'
    local assets_state='missing'
    if [[ "$script_status" == 'present' && "$snippet_status" == 'present' ]]; then
      assets_state='installed'
    elif [[ "$script_status" == 'present' || "$snippet_status" == 'present' ]]; then
      assets_state='partial'
    fi
    local tester='missing'
    if command -v nginx >/dev/null 2>&1; then
      tester='nginx'
    elif command -v openresty >/dev/null 2>&1; then
      tester='openresty'
    fi
    local instructions_label
    local install_label
    local remove_label
    local test_label
    printf -v instructions_label 'Show integration instructions (script: %s, snippet: %s)' "$script_status" "$snippet_status"
    printf -v install_label 'Install/refresh Lua challenge assets (%s)' "$assets_state"
    printf -v remove_label 'Remove Lua challenge assets (%s)' "$assets_state"
    printf -v test_label 'Run nginx/openresty configuration test (%s)' "$tester"
    local choice
    choice=$(SentinelForge_ui_display_menu 'Nginx/OpenResty anti-DDoS' \
      '1' "$instructions_label" \
      '2' "$install_label" \
      '3' "$remove_label" \
      '4' "$test_label" \
      '5' 'Back')
    case "$choice" in
      1) SentinelForge_ddos_nginx_show_instructions ;;
      2) SentinelForge_ddos_nginx_install_assets ;;
      3) SentinelForge_ddos_nginx_remove_assets ;;
      4)
        if ! SentinelForge_ddos_nginx_test_config; then
          :
        fi
        ;;
      5|'') return ;;
    esac
  done
}

SentinelForge_ddos_manage_blocklist_menu() {
  while true; do
    local choice
    choice=$(SentinelForge_ui_display_menu 'DDoS blocklist' \
      '1' 'View current blocklist' \
      '2' 'View top talkers (live)' \
      '3' 'Add IP to blocklist' \
      '4' 'Remove IP from blocklist' \
      '5' 'Clear blocklist' \
      '6' 'Back')
    case "$choice" in
      1) SentinelForge_ddos_list_blocked ;;
      2) SentinelForge_ddos_view_top_talkers ;;
      3) SentinelForge_ddos_prompt_block_ip ;;
      4) SentinelForge_ddos_prompt_unblock_ip ;;
      5) SentinelForge_ddos_clear_blocklist ;;
      6|'') return ;;
    esac
  done
}

SentinelForge_ddos_menu() {
  local refresh_needed=1
  while true; do
    if (( refresh_needed )); then
      SentinelForge_ddos_refresh_state
      refresh_needed=0
    fi
    local guard=${SENTINELFORGE_STATE[ddos_guard]:-disabled}
    local sysctl=${SENTINELFORGE_STATE[ddos_sysctl]:-no}
    local blocklist=${SENTINELFORGE_STATE[ddos_blocklist]:-0 entries}
    local nginx=${SENTINELFORGE_STATE[ddos_nginx]:-missing}
    local guard_label
    local blocklist_label
    local kernel_label
    local nginx_label
    local kernel_state=$sysctl
    if [[ ${kernel_state,,} == yes ]]; then
      kernel_state='applied'
    else
      kernel_state='not applied'
    fi
    printf -v guard_label 'Enable/Disable SentinelForge DDoS guard (%s)' "$guard"
    printf -v blocklist_label 'Manage dynamic blocklist (%s)' "$blocklist"
    printf -v kernel_label 'Enable/Disable kernel hardening profile (%s)' "$kernel_state"
    printf -v nginx_label 'Open Nginx/OpenResty challenge menu (%s)' "$nginx"
    local choice
    choice=$(SentinelForge_ui_display_menu 'DDoS protection' \
      '1' "View DDoS status (guard: ${guard}, kernel: ${sysctl})" \
      '2' "$guard_label" \
      '3' "$blocklist_label" \
      '4' "$kernel_label" \
      '5' 'Gatekeeper readiness checks' \
      '6' "$nginx_label" \
      '7' 'Back')
    case "$choice" in
      1) SentinelForge_ddos_show_overview ;;
      2)
        if [[ ${SENTINELFORGE_STATE[ddos_guard]:-disabled} == 'enabled' ]]; then
          SentinelForge_ddos_remove_guard
        else
          SentinelForge_ddos_apply_guard
        fi
        refresh_needed=1
        ;;
      3)
        SentinelForge_ddos_manage_blocklist_menu
        refresh_needed=1
        ;;
      4)
        if [[ ${SENTINELFORGE_STATE[ddos_sysctl]:-no} == 'yes' ]]; then
          SentinelForge_ddos_remove_kernel_profile
        else
          SentinelForge_ddos_apply_kernel_profile
        fi
        refresh_needed=1
        ;;
      5)
        SentinelForge_ddos_gatekeeper_readiness
        ;;
      6)
        SentinelForge_ddos_nginx_menu
        refresh_needed=1
        ;;
      7|'') return ;;
    esac
  done
}
