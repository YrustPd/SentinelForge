#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

declare -ag SENTINELFORGE_SSH_WARNINGS=()
declare -ag SENTINELFORGE_SSH_SUGGESTIONS=()

SentinelForge_ssh_refresh_state() {
  SentinelForge_detect_sshd_test_config || true
  local ssh_port=${SENTINELFORGE_SSHD_DATA[port]:-22}
  SENTINELFORGE_STATE[ssh_port]="$ssh_port"
  SENTINELFORGE_STATE[ssh_password_auth]="${SENTINELFORGE_SSHD_DATA[passwordauthentication]:-yes}"
  SENTINELFORGE_STATE[ssh_pubkey_auth]="${SENTINELFORGE_SSHD_DATA[pubkeyauthentication]:-yes}"
  SENTINELFORGE_STATE[ssh_permit_root]="${SENTINELFORGE_SSHD_DATA[permitrootlogin]:-prohibit-password}"
  SENTINELFORGE_STATE[ssh_login_grace]="${SENTINELFORGE_SSHD_DATA[logingracetime]:-120}"
  SentinelForge_detect_primary_user >/dev/null
  local auth_file="${SENTINELFORGE_FACTS[primary_home]:-}/.ssh/authorized_keys"
  local ed25519=0 rsa=0 ecdsa=0 total=0
  if [[ -f "$auth_file" ]]; then
    while IFS= read -r line; do
      [[ -z ${line// } ]] && continue
      [[ $line == \#* ]] && continue
      case "$line" in
        ssh-ed25519*) ((++ed25519)); ((++total)); ;;
        ssh-rsa*) ((++rsa)); ((++total)); ;;
        ecdsa-sha2-nistp256*) ((++ecdsa)); ((++total)); ;;
      esac
    done <"$auth_file"
  fi
  SENTINELFORGE_STATE[ssh_key_ed25519]=$ed25519
  SENTINELFORGE_STATE[ssh_key_rsa]=$rsa
  SENTINELFORGE_STATE[ssh_key_ecdsa]=$ecdsa
  SENTINELFORGE_STATE[ssh_key_total]=$total

  local exposures=0
  local listeners
  listeners=$(SentinelForge_detect_public_listeners)
  if [[ -n "$listeners" ]]; then
    exposures=$(wc -l <<<"$listeners" | awk '{print $1}')
    if grep -qE '0\.0\.0\.0:22|:::22' <<<"$listeners"; then
      SENTINELFORGE_STATE[ssh_public_22]='yes'
    else
      SENTINELFORGE_STATE[ssh_public_22]='no'
    fi
  else
    SENTINELFORGE_STATE[ssh_public_22]='no'
  fi
  SENTINELFORGE_STATE[public_listeners]=$exposures

  SentinelForge_ssh_build_audit
}

SentinelForge_ssh_build_audit() {
  SENTINELFORGE_SSH_WARNINGS=()
  SENTINELFORGE_SSH_SUGGESTIONS=()
  local config_file
  config_file=$(SentinelForge_detect_sshd_config)
  if [[ -f "$config_file" ]]; then
    local normalized
    normalized=$(sed -E 's/[[:space:]]+/ /g; s/^ //; /^#/d; /^[[:space:]]*$/d' "$config_file")
    local value
    while IFS= read -r line; do
      local key=${line%% *}
      value=${line#* }
      case ${key,,} in
        passwordauthentication)
          if [[ ${value,,} == yes ]]; then
            SENTINELFORGE_SSH_WARNINGS+=('PasswordAuthentication yes (use key-based auth)')
            SENTINELFORGE_SSH_SUGGESTIONS+=('Set PasswordAuthentication no')
          fi
          ;;
        permitrootlogin)
          if [[ ${value,,} == yes ]]; then
            SENTINELFORGE_SSH_WARNINGS+=('PermitRootLogin yes exposes root login')
            SENTINELFORGE_SSH_SUGGESTIONS+=('Set PermitRootLogin prohibit-password or no')
          fi
          ;;
        kbdinteractiveauthentication)
          if [[ ${value,,} == yes ]]; then
            SENTINELFORGE_SSH_WARNINGS+=('Keyboard-interactive authentication enabled')
            SENTINELFORGE_SSH_SUGGESTIONS+=('Set KbdInteractiveAuthentication no')
          fi
          ;;
        ciphers)
          if grep -qi 'cbc' <<<"$value"; then
            SENTINELFORGE_SSH_WARNINGS+=('Weak CBC ciphers present')
            SENTINELFORGE_SSH_SUGGESTIONS+=('Use chacha20-poly1305@openssh.com,aes256-gcm@openssh.com')
          fi
          if ! grep -q 'chacha20-poly1305@openssh.com' <<<"$value"; then
            SENTINELFORGE_SSH_SUGGESTIONS+=('Add chacha20-poly1305@openssh.com to Ciphers')
          fi
          ;;
        macs)
          if grep -qi 'hmac-md5' <<<"$value"; then
            SENTINELFORGE_SSH_WARNINGS+=('Legacy HMAC-MD5 MACs detected')
            SENTINELFORGE_SSH_SUGGESTIONS+=('Use hmac-sha2-512,hmac-sha2-256')
          fi
          ;;
        kexalgorithms)
          if grep -qi 'diffie-hellman-group1' <<<"$value" || grep -qi 'diffie-hellman-group14' <<<"$value"; then
            SENTINELFORGE_SSH_WARNINGS+=('Weak Diffie-Hellman groups configured')
            SENTINELFORGE_SSH_SUGGESTIONS+=('Use curve25519-sha256 and diffie-hellman-group-exchange-sha256')
          fi
          ;;
        hostkeyalgorithms)
          if [[ ${value,,} == ssh-rsa ]]; then
            SENTINELFORGE_SSH_WARNINGS+=('Only ssh-rsa host key configured')
            SENTINELFORGE_SSH_SUGGESTIONS+=('Add HostKey for ed25519 (/etc/ssh/ssh_host_ed25519_key)')
          fi
          ;;
      esac
    done <<<"$normalized"
  fi

  if [[ ${SENTINELFORGE_STATE[ssh_password_auth]:-yes} == yes && ${SENTINELFORGE_STATE[ssh_key_total]:-0} -eq 0 ]]; then
    SENTINELFORGE_SSH_WARNINGS+=('No SSH keys detected; disabling passwords would lock you out')
  fi
}

SentinelForge_ssh_show_audit() {
  SentinelForge_ssh_refresh_state
  SentinelForge_ssh_show_status_panel
}

SentinelForge_ssh_add_public_key() {
  SentinelForge_detect_primary_user >/dev/null
  local user="${SENTINELFORGE_FACTS[primary_user]}"
  local home="${SENTINELFORGE_FACTS[primary_home]}"
  local ssh_dir="${home}/.ssh"
  local auth_file="${ssh_dir}/authorized_keys"
  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  chown "$user:" "$ssh_dir" 2>/dev/null || true
  local key
  key=$(SentinelForge_ui_prompt_input "Paste the public key for ${user}: ")
  local prompt_status=${SENTINELFORGE_UI_LAST_STATUS:-ok}
  if [[ $prompt_status == 'cancel' ]]; then
    return 0
  elif [[ $prompt_status == 'error' ]]; then
    SentinelForge_ui_show_message 'SSH' 'Failed to read input. Please try again.'
    return 1
  fi
  key=${key//[$'\r\n']/}
  if [[ -z "$key" ]]; then
    SentinelForge_ui_show_message 'SSH' 'No key provided.'
    return 0
  fi
  if ! grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256)' <<<"$key"; then
    SentinelForge_ui_show_message 'SSH' 'Unsupported key type. Provide ssh-ed25519, ssh-rsa, or ecdsa-sha2-nistp256.'
    return 0
  fi
  touch "$auth_file"
  chmod 600 "$auth_file"
  chown "$user:" "$auth_file" 2>/dev/null || true
  if grep -qxF "$key" "$auth_file" 2>/dev/null; then
    SentinelForge_ui_show_message 'SSH' 'Key already present.'
    return 0
  fi
  echo "$key" >>"$auth_file"
  chown "$user:" "$auth_file" 2>/dev/null || true
  SentinelForge_ui_show_message 'SSH' "Key added for ${user}."
}

SentinelForge_ssh_validate_config() {
  local sshd_path
  sshd_path=$(SentinelForge_detect_sshd_path) || return 1
  [[ -z "$sshd_path" ]] && return 1
  "$sshd_path" -t >/dev/null 2>&1
}

SentinelForge_ssh_disable_password_login() {
  SentinelForge_utils_require_root
  SentinelForge_ssh_refresh_state
  if [[ ${SENTINELFORGE_STATE[ssh_password_auth]} == "no" ]]; then
    SentinelForge_ui_show_message 'SSH' 'Password authentication already disabled.'
    return 0
  fi
  if [[ ${SENTINELFORGE_STATE[ssh_key_total]} -eq 0 ]]; then
    SentinelForge_ui_show_message 'SSH' 'No authorized keys detected. Add a key before disabling passwords.'
    return 1
  fi
  if ! SentinelForge_ui_prompt_confirm "Disable password authentication for SSH?"; then
    return 0
  fi
  local config
  config=$(SentinelForge_detect_sshd_config)
  local backup
  backup=$(SentinelForge_utils_backup_file "$config" 'systemctl reload ssh') || true
  sed -i -E 's/^[#[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication no/I' "$config"
  sed -i -E 's/^[#[:space:]]*KbdInteractiveAuthentication[[:space:]].*/KbdInteractiveAuthentication no/I' "$config"
  if ! grep -qi '^PasswordAuthentication' "$config"; then
    echo 'PasswordAuthentication no' >>"$config"
  fi
  if ! grep -qi '^KbdInteractiveAuthentication' "$config"; then
    echo 'KbdInteractiveAuthentication no' >>"$config"
  fi
  if ! grep -qi '^PubkeyAuthentication' "$config"; then
    echo 'PubkeyAuthentication yes' >>"$config"
  else
    sed -i -E 's/^[#[:space:]]*PubkeyAuthentication[[:space:]].*/PubkeyAuthentication yes/I' "$config"
  fi
  if ! SentinelForge_ssh_validate_config; then
    [[ -n "$backup" ]] && cp "$backup" "$config"
    SentinelForge_ui_show_message 'SSH' 'Validation failed. Configuration restored from backup.'
    return 1
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || true
  local msg
  printf -v msg 'Password authentication disabled. Backup: %s' "${backup:-n/a}"
  SentinelForge_ui_show_message 'SSH' "$msg"
}

SentinelForge_ssh_port_in_use() {
  local port=$1
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v p="$port" 'NR>1 {split($4,a,":"); if (a[length(a)] == p) {found=1; exit}} END {exit(found?0:1)}'
    return
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk -v p="$port" 'NR>2 {split($4,a,":"); if (a[length(a)] == p) {found=1; exit}} END {exit(found?0:1)}'
    return
  fi
  return 1
}

SentinelForge_ssh_change_port() {
  SentinelForge_utils_require_root
  SentinelForge_ssh_refresh_state
  local current_port=${SENTINELFORGE_STATE[ssh_port]}
  local new_port
  new_port=$(SentinelForge_ui_prompt_input "Enter new SSH port (1-65535): " "$current_port")
  local prompt_status=${SENTINELFORGE_UI_LAST_STATUS:-ok}
  if [[ $prompt_status == 'cancel' ]]; then
    SentinelForge_ui_show_message 'SSH' 'Port change cancelled.'
    return 0
  elif [[ $prompt_status == 'error' ]]; then
    SentinelForge_ui_show_message 'SSH' 'Failed to read input. Please try again.'
    return 1
  fi
  if [[ -z "$new_port" || ! "$new_port" =~ ^[0-9]+$ || $new_port -lt 1 || $new_port -gt 65535 ]]; then
    SentinelForge_ui_show_message 'SSH' 'Invalid port selected.'
    return 0
  fi
  if [[ "$new_port" == "$current_port" ]]; then
    SentinelForge_ui_show_message 'SSH' 'Port unchanged.'
    return 0
  fi
  if SentinelForge_ssh_port_in_use "$new_port"; then
    SentinelForge_ui_show_message 'SSH' "Port ${new_port} already in use."
    return 0
  fi
  SentinelForge_firewall_ensure_port "$new_port"
  local keep_old='no'
  if SentinelForge_ui_prompt_confirm "Keep old port ${current_port} open temporarily?"; then
    keep_old='yes'
    SentinelForge_firewall_ensure_port "$current_port"
  fi
  local config
  config=$(SentinelForge_detect_sshd_config)
  local backup
  backup=$(SentinelForge_utils_backup_file "$config" 'systemctl reload ssh') || true
  if grep -qiE '^[#[:space:]]*Port[[:space:]]+[0-9]+' "$config"; then
    sed -i -E "0,/^[#[:space:]]*Port[[:space:]]+[0-9]+/s//Port ${new_port}/" "$config"
  else
    echo "Port ${new_port}" >>"$config"
  fi
  if [[ "$keep_old" == 'no' ]]; then
    sed -i -E "/^[#[:space:]]*Port[[:space:]]+${current_port}[[:space:]]*$/Id" "$config"
  fi
  if ! SentinelForge_ssh_validate_config; then
    [[ -n "$backup" ]] && cp "$backup" "$config"
    SentinelForge_ui_show_message 'SSH' 'Validation failed. Restored previous configuration.'
    return 1
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || true
  local msg
  printf -v msg 'SSH port changed to %s. Backup: %s' "$new_port" "${backup:-n/a}"
  if [[ "$keep_old" == 'yes' ]]; then
    msg+=$"\nReminder: remove old port ${current_port} once connectivity is confirmed."
  fi
  SentinelForge_ui_show_message 'SSH' "$msg"
}

SentinelForge_ssh_status_report() {
  SentinelForge_ssh_refresh_state
  local report=""
  printf -v report 'Port: %s\nPasswordAuthentication: %s\nPubkeyAuthentication: %s\nPermitRootLogin: %s\nAuthorized keys — ed25519:%s rsa:%s ecdsa:%s (total %s)\n' \
    "${SENTINELFORGE_STATE[ssh_port]}" \
    "${SENTINELFORGE_STATE[ssh_password_auth]}" \
    "${SENTINELFORGE_STATE[ssh_pubkey_auth]}" \
    "${SENTINELFORGE_STATE[ssh_permit_root]}" \
    "${SENTINELFORGE_STATE[ssh_key_ed25519]}" \
    "${SENTINELFORGE_STATE[ssh_key_rsa]}" \
    "${SENTINELFORGE_STATE[ssh_key_ecdsa]}" \
    "${SENTINELFORGE_STATE[ssh_key_total]}"
  if ((${#SENTINELFORGE_SSH_WARNINGS[@]} > 0)); then
    report+=$'\nFindings:\n'
    local item
    for item in "${SENTINELFORGE_SSH_WARNINGS[@]}"; do
      report+="  - ${item}\n"
    done
  else
    report+=$'\nNo major SSH findings detected.\n'
  fi
  if ((${#SENTINELFORGE_SSH_SUGGESTIONS[@]} > 0)); then
    report+=$'\nRecommendations:\n'
    local rec
    for rec in "${SENTINELFORGE_SSH_SUGGESTIONS[@]}"; do
      report+="  - ${rec}\n"
    done
  fi
  report+=$"\nConfig file: $(SentinelForge_detect_sshd_config)\n"
  printf '%s' "$report"
}

SentinelForge_ssh_show_status_panel() {
  local report
  report=$(SentinelForge_ssh_status_report)
  SentinelForge_ui_show_textbox 'SSH status' "$report" 22 78
}

SentinelForge_ssh_enable_password_login() {
  SentinelForge_utils_require_root
  SentinelForge_ssh_refresh_state
  if [[ ${SENTINELFORGE_STATE[ssh_password_auth]} == "yes" ]]; then
    SentinelForge_ui_show_message 'SSH' 'Password authentication is already enabled.'
    return 0
  fi
  if ! SentinelForge_ui_prompt_confirm "Enable password authentication for SSH?" false; then
    return 0
  fi
  if SentinelForge_ssh_update_config_option 'PasswordAuthentication' 'yes'; then
    SentinelForge_ui_show_message 'SSH' 'Password authentication enabled.'
    return 0
  fi
  SentinelForge_ui_show_message 'SSH' 'Failed to enable password authentication. Config restored.'
  return 1
}

SentinelForge_ssh_toggle_password_login() {
  SentinelForge_ssh_refresh_state
  if [[ ${SENTINELFORGE_STATE[ssh_password_auth]} == "yes" ]]; then
    SentinelForge_ssh_disable_password_login
  else
    SentinelForge_ssh_enable_password_login
  fi
}

SentinelForge_ssh_disable_root_login() {
  SentinelForge_utils_require_root
  SentinelForge_ssh_refresh_state
  local current=${SENTINELFORGE_STATE[ssh_permit_root]:-prohibit-password}
  if [[ ${current,,} != yes ]]; then
    SentinelForge_ui_show_message 'SSH' 'PermitRootLogin already restricted.'
    return 0
  fi
  if ! SentinelForge_ui_prompt_confirm "Switch PermitRootLogin to prohibit-password?"; then
    return 0
  fi
  if SentinelForge_ssh_update_config_option 'PermitRootLogin' 'prohibit-password'; then
    SentinelForge_ui_show_message 'SSH' 'PermitRootLogin set to prohibit-password.'
    return 0
  fi
  SentinelForge_ui_show_message 'SSH' 'Failed to update PermitRootLogin.'
  return 1
}

SentinelForge_ssh_enable_root_login() {
  SentinelForge_utils_require_root
  SentinelForge_ssh_refresh_state
  local current=${SENTINELFORGE_STATE[ssh_permit_root]:-prohibit-password}
  if [[ ${current,,} == yes ]]; then
    SentinelForge_ui_show_message 'SSH' 'PermitRootLogin already set to yes.'
    return 0
  fi
  if ! SentinelForge_ui_prompt_confirm "Allow root SSH logins (PermitRootLogin yes)?" false; then
    return 0
  fi
  if SentinelForge_ssh_update_config_option 'PermitRootLogin' 'yes'; then
    SentinelForge_ui_show_message 'SSH' 'PermitRootLogin set to yes.'
    return 0
  fi
  SentinelForge_ui_show_message 'SSH' 'Failed to update PermitRootLogin.'
  return 1
}

SentinelForge_ssh_toggle_root_login() {
  SentinelForge_ssh_refresh_state
  if [[ ${SENTINELFORGE_STATE[ssh_permit_root]:-prohibit-password,,} == yes ]]; then
    SentinelForge_ssh_disable_root_login
  else
    SentinelForge_ssh_enable_root_login
  fi
}

SentinelForge_ssh_update_config_option() {
  local key=$1
  local value=$2
  local config
  config=$(SentinelForge_detect_sshd_config)
  local backup
  backup=$(SentinelForge_utils_backup_file "$config" 'systemctl reload ssh') || true
  if grep -qiE "^[#[:space:]]*${key}[[:space:]]+" "$config"; then
    sed -i -E "s/^[#[:space:]]*${key}[[:space:]].*/${key} ${value}/I" "$config"
  else
    echo "${key} ${value}" >>"$config"
  fi
  if ! SentinelForge_ssh_validate_config; then
    [[ -n "$backup" ]] && cp "$backup" "$config"
    return 1
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || true
  SentinelForge_utils_info "Updated ${key} to ${value} (backup: ${backup:-n/a})"
  return 0
}
