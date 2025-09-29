#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SENTINELFORGE_UI_LAST_STATUS=''

SentinelForge_ui_has_whiptail() {
  command -v whiptail >/dev/null 2>&1
}

SentinelForge_ui_run_whiptail() {
  local restore_errexit=0
  local restore_errtrace=0
  if [[ $- == *e* ]]; then
    restore_errexit=1
    set +e
  fi
  if [[ $- == *E* ]]; then
    restore_errtrace=1
    set +E
  fi
  "$@"
  local status=$?
  if (( restore_errtrace )); then
    set -E
  fi
  if (( restore_errexit )); then
    set -e
  fi
  return $status
}

SentinelForge_ui_safe_read() {
  local prompt=$1
  local __var=$2
  local value=""
  if IFS= read -r -p "$prompt" value; then
    printf -v "${__var}" '%s' "${value}"
    return 0
  fi
  return 1
}

SentinelForge_ui_prompt_confirm() {
  local message=$1 default_no=${2:-true}
  if SentinelForge_ui_has_whiptail; then
    if whiptail --backtitle "${SENTINELFORGE_MENU_BACKTITLE}" --yesno "$message" 12 72; then
      SENTINELFORGE_UI_LAST_STATUS='ok'
      return 0
    fi
    SENTINELFORGE_UI_LAST_STATUS='cancel'
    return 1
  fi
  local prompt
  if [[ "$default_no" == true ]]; then
    prompt="$message (y/N): "
    local answer=""
    if SentinelForge_ui_safe_read "$prompt" answer; then
      SENTINELFORGE_UI_LAST_STATUS='ok'
      [[ "$answer" =~ ^[Yy]$ ]]
    else
      SENTINELFORGE_UI_LAST_STATUS='cancel'
      return 1
    fi
  else
    prompt="$message (Y/n): "
    local answer=""
    if SentinelForge_ui_safe_read "$prompt" answer; then
      SENTINELFORGE_UI_LAST_STATUS='ok'
      [[ -z "$answer" || "$answer" =~ ^[Yy]$ ]]
    else
      SENTINELFORGE_UI_LAST_STATUS='cancel'
      return 0
    fi
  fi
}

SentinelForge_ui_prompt_input() {
  local message=$1 default_value=${2:-}
  if SentinelForge_ui_has_whiptail; then
    local result='' status=0
    if result=$(SentinelForge_ui_run_whiptail \
      whiptail --backtitle "${SENTINELFORGE_MENU_BACKTITLE}" --inputbox "$message" 12 72 "$default_value" \
      3>&1 1>&2 2>&3); then
      status=0
    else
      status=$?
    fi
    if (( status == 0 )); then
      SENTINELFORGE_UI_LAST_STATUS='ok'
      printf '%s' "${result}"
    elif (( status == 1 || status == 255 )); then
      SENTINELFORGE_UI_LAST_STATUS='cancel'
    else
      SENTINELFORGE_UI_LAST_STATUS='error'
    fi
    return 0
  fi
  local answer=""
  if SentinelForge_ui_safe_read "$message" answer; then
    SENTINELFORGE_UI_LAST_STATUS='ok'
    if [[ -z "$answer" && -n "$default_value" ]]; then
      printf '%s' "$default_value"
    else
      printf '%s' "$answer"
    fi
  else
    SENTINELFORGE_UI_LAST_STATUS='cancel'
  fi
}

SentinelForge_ui_prompt_continue() {
  local dummy=""
  SentinelForge_ui_safe_read "Press Enter to continue..." dummy || true
}

SentinelForge_ui_show_message() {
  local title=$1
  local message=$2
  local height=${3:-14}
  local width=${4:-60}
  local backtitle=${SENTINELFORGE_MENU_BACKTITLE:-'SentinelForge'}
  if SentinelForge_ui_has_whiptail; then
    local status=0
    if SentinelForge_ui_run_whiptail \
      whiptail --title "${title}" --backtitle "${backtitle}" --msgbox "${message}" "${height}" "${width}"; then
      status=0
    else
      status=$?
    fi
    if (( status == 0 )); then
      SENTINELFORGE_UI_LAST_STATUS='shown'
    elif (( status == 1 || status == 255 )); then
      SENTINELFORGE_UI_LAST_STATUS='cancel'
    else
      SENTINELFORGE_UI_LAST_STATUS='error'
    fi
    return 0
  fi
  printf '\n%s\n%s\n\n' "${title}" "${message}"
  printf 'Press Enter to continue...\n'
  read -r _ || true
  SENTINELFORGE_UI_LAST_STATUS='shown'
}

SentinelForge_ui_show_textbox() {
  local title=$1
  local content=$2
  local height=${3:-20}
  local width=${4:-78}
  local backtitle=${SENTINELFORGE_MENU_BACKTITLE:-'SentinelForge'}
  if SentinelForge_ui_has_whiptail; then
    local tmp status=0
    tmp=$(mktemp "${TMPDIR:-/tmp}/sentinelforge-text.XXXXXX")
    printf '%s\n \n' "${content}" >"${tmp}"
    if SentinelForge_ui_run_whiptail \
      whiptail --title "${title}" --backtitle "${backtitle}" --scrolltext --textbox "${tmp}" "${height}" "${width}"; then
      status=0
    else
      status=$?
    fi
    rm -f "${tmp}"
    if (( status == 0 )); then
      SENTINELFORGE_UI_LAST_STATUS='shown'
    elif (( status == 1 || status == 255 )); then
      SENTINELFORGE_UI_LAST_STATUS='cancel'
    else
      SENTINELFORGE_UI_LAST_STATUS='error'
    fi
    return 0
  fi
  printf '\n%s\n%s\n\n' "${title}" "${content}"
  read -r _ || true
  SENTINELFORGE_UI_LAST_STATUS='shown'
}

SentinelForge_ui_display_menu() {
  local title=$1
  shift
  local -a options=("$@")
  local backtitle=${SENTINELFORGE_MENU_BACKTITLE:-'Maintainer: YrustPd | Repo: https://github.com/YrustPd/SentinelForge'}
  if SentinelForge_ui_has_whiptail; then
    local choice='' status=0
    if choice=$(SentinelForge_ui_run_whiptail \
      whiptail \
      --title "${title}" \
      --backtitle "${backtitle}" \
      --ok-button "Select" \
      --cancel-button "Exit" \
      --menu "Select an option" 24 78 14 "${options[@]}" \
      3>&1 1>&2 2>&3); then
      status=0
    else
      status=$?
    fi
    if (( status == 0 )); then
      SENTINELFORGE_UI_LAST_STATUS='ok'
      printf '%s' "$choice"
    elif (( status == 1 || status == 255 )); then
      SENTINELFORGE_UI_LAST_STATUS='cancel'
    else
      SENTINELFORGE_UI_LAST_STATUS='error'
    fi
    return 0
  fi
  printf '%s\n%s\n' "$title" "$backtitle"
  local i=0
  while (( i < ${#options[@]} )); do
    printf '%s) %s\n' "${options[i]}" "${options[i+1]}"
    ((i+=2))
  done
  local answer=""
  if SentinelForge_ui_safe_read "Choose an option: " answer; then
    SENTINELFORGE_UI_LAST_STATUS='ok'
    printf '%s' "${answer}"
  else
    SENTINELFORGE_UI_LAST_STATUS='cancel'
  fi
}
