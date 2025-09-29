#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

declare -Ag SENTINELFORGE_STATE=()

SentinelForge_score_compute() {
  local score=0
  local deductions=0

  [[ ${SENTINELFORGE_STATE[ssh_password_auth]:-no} == "no" ]] && ((score += 20))
  case ${SENTINELFORGE_STATE[ssh_permit_root]:-prohibit-password} in
    no|prohibit-password) ((score += 10)) ;;
  esac
  [[ ${SENTINELFORGE_STATE[ssh_pubkey_auth]:-yes} == "yes" ]] && ((score += 5))

  if [[ ${SENTINELFORGE_STATE[ssh_port]:-22} != "22" ]]; then
    ((score += 10))
  fi
  if [[ ${SENTINELFORGE_STATE[firewall_enabled]:-no} == "yes" ]]; then
    case ${SENTINELFORGE_STATE[firewall_default_in]:-allow} in
      deny|drop|reject) ((score += 15)) ;;
    esac
    [[ ${SENTINELFORGE_STATE[firewall_ssh_allowed]:-no} == "yes" ]] && ((score += 5))
  fi
  [[ ${SENTINELFORGE_STATE[ssh_rate_limit]:-no} == "yes" ]] && ((score += 10))
  [[ ${SENTINELFORGE_STATE[ddos_guard]:-disabled} == "enabled" ]] && ((score += 10))
  [[ ${SENTINELFORGE_STATE[ddos_sysctl]:-no} == "yes" ]] && ((score += 5))
  [[ ${SENTINELFORGE_STATE[ddos_nginx]:-missing} == "installed" ]] && ((score += 5))
  [[ ${SENTINELFORGE_STATE[fail2ban_sshd]:-no} == "yes" ]] && ((score += 15))
  [[ ${SENTINELFORGE_STATE[sysctl_applied]:-no} == "yes" ]] && ((score += 10))
  [[ ${SENTINELFORGE_STATE[unattended_enabled]:-no} == "yes" ]] && ((score += 5))

  if [[ ${SENTINELFORGE_STATE[ssh_password_auth]:-no} == "yes" && ${SENTINELFORGE_STATE[ssh_key_total]:-0} -eq 0 ]]; then
    ((deductions += 25))
  fi
  if [[ ${SENTINELFORGE_STATE[ssh_password_auth]:-no} == "yes" && ${SENTINELFORGE_STATE[ssh_port]:-22} == "22" ]]; then
    if [[ ${SENTINELFORGE_STATE[ssh_public_22]:-no} == "yes" ]]; then
      ((deductions += 20))
    fi
  fi
  local listeners=${SENTINELFORGE_STATE[public_listeners]:-0}
  if (( listeners > 10 )); then
    ((deductions += 15))
  elif (( listeners > 5 )); then
    ((deductions += 10))
  elif (( listeners > 3 )); then
    ((deductions += 5))
  fi

  score=$((score - deductions))
  (( score < 0 )) && score=0
  (( score > 100 )) && score=100

  SENTINELFORGE_STATE[security_score]=$score
  local label
  if (( score <= 34 )); then
    label='Poor'
  elif (( score <= 59 )); then
    label='Fair'
  elif (( score <= 79 )); then
    label='Good'
  elif (( score <= 89 )); then
    label='Strong'
  else
    label='Hardened'
  fi
  SENTINELFORGE_STATE[security_label]=$label
  SENTINELFORGE_STATE[security_bar]=$(SentinelForge_colors_progress_bar "$score" "$label" 30)
}
