#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SentinelForge_sysctl_profile_path='/etc/sysctl.d/99-sentinelforge.conf'

SentinelForge_sysctl_show_recommendations() {
  cat <<'CONF'
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=4096
net.netfilter.nf_conntrack_max=262144
net.ipv4.icmp_ratelimit=100
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
CONF
}

SentinelForge_sysctl_recommendations_summary() {
  cat <<'SUMMARY'
Recommended hardening tweaks:
  net.ipv4.tcp_syncookies=1              – Resist SYN flood attempts on IPv4 sockets
  net.ipv4.conf.*.rp_filter=1            – Drop spoofed source packets (reverse-path filtering)
  net.core.somaxconn=4096                – Allow larger backlog for queued connections
  net.ipv4.tcp_max_syn_backlog=4096      – Increase pending handshake queue length
  net.netfilter.nf_conntrack_max=262144  – Raise conntrack table size for busy hosts
  net.ipv4.icmp_ratelimit=100            – Rate-limit ICMP replies to reduce abuse
  net.ipv4.icmp_echo_ignore_broadcasts=1 – Ignore broadcast pings used for amplification
  net.ipv4.conf.*.accept_source_route=0  – Block dangerous source-routed packets
  net.ipv4.conf.*.accept_redirects=0     – Reject ICMP redirects that can hijack sessions

The profile written to /etc/sysctl.d/99-sentinelforge.conf contains only the key=value lines above.
SUMMARY
}

SentinelForge_sysctl_refresh_state() {
  if [[ -f "$SentinelForge_sysctl_profile_path" ]]; then
    SENTINELFORGE_STATE[sysctl_applied]='yes'
  else
    SENTINELFORGE_STATE[sysctl_applied]='no'
  fi
}

SentinelForge_sysctl_apply() {
  SentinelForge_utils_require_root
  local summary profile
  summary=$(SentinelForge_sysctl_recommendations_summary)
  profile=$(SentinelForge_sysctl_show_recommendations)
  SentinelForge_ui_show_textbox 'Sysctl recommendations' "$summary\n\nProfile values:\n${profile}" 22 78
  if ! SentinelForge_ui_prompt_confirm "Write profile to ${SentinelForge_sysctl_profile_path} and apply?"; then
    SentinelForge_ui_show_message 'Sysctl' 'No changes applied.'
    return 0
  fi
  local backup=""
  if [[ -f "$SentinelForge_sysctl_profile_path" ]]; then
    backup=$(SentinelForge_utils_backup_file "$SentinelForge_sysctl_profile_path" 'sysctl --system') || true
  fi
  mkdir -p "$(dirname "$SentinelForge_sysctl_profile_path")"
  {
    echo '# Managed by SentinelForge'
    SentinelForge_sysctl_show_recommendations
  } >"$SentinelForge_sysctl_profile_path"
  if sysctl --system >/dev/null 2>&1; then
    local msg='Sysctl profile applied.'
    if [[ -n "$backup" ]]; then
      msg+=$"\nPrevious file backup: ${backup}"
    fi
    SentinelForge_ui_show_message 'Sysctl' "$msg"
  else
    if [[ -n "$backup" ]]; then
      cp "$backup" "$SentinelForge_sysctl_profile_path"
    else
      rm -f "$SentinelForge_sysctl_profile_path"
    fi
    SentinelForge_ui_show_message 'Sysctl' 'Failed to apply sysctl. Restored previous file.'
    return 1
  fi
}
