#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

SentinelForge_colors_init() {
  if [[ -t 1 ]]; then
    SENTINELFORGE_COLOR_RESET=$'\033[0m'
    SENTINELFORGE_COLOR_BOLD=$'\033[1m'
    SENTINELFORGE_COLOR_DIM=$'\033[2m'
    SENTINELFORGE_COLOR_RED=$'\033[31m'
    SENTINELFORGE_COLOR_GREEN=$'\033[32m'
    SENTINELFORGE_COLOR_YELLOW=$'\033[33m'
    SENTINELFORGE_COLOR_BLUE=$'\033[34m'
    SENTINELFORGE_COLOR_MAGENTA=$'\033[35m'
    SENTINELFORGE_COLOR_CYAN=$'\033[36m'
    SENTINELFORGE_COLOR_WHITE=$'\033[37m'
  else
    SENTINELFORGE_COLOR_RESET=""
    SENTINELFORGE_COLOR_BOLD=""
    SENTINELFORGE_COLOR_DIM=""
    SENTINELFORGE_COLOR_RED=""
    SENTINELFORGE_COLOR_GREEN=""
    SENTINELFORGE_COLOR_YELLOW=""
    SENTINELFORGE_COLOR_BLUE=""
    SENTINELFORGE_COLOR_MAGENTA=""
    SENTINELFORGE_COLOR_CYAN=""
    SENTINELFORGE_COLOR_WHITE=""
  fi
}

SentinelForge_colors_banner() {
  local title=$1 color=${2:-$SENTINELFORGE_COLOR_CYAN}
  local border="========================================"
  printf '%s%s%s\n' "$color" "$border" "$SENTINELFORGE_COLOR_RESET"
  printf '%s  %s  %s\n' "$color" "$title" "$SENTINELFORGE_COLOR_RESET"
  printf '%s%s%s\n' "$color" "$border" "$SENTINELFORGE_COLOR_RESET"
}

SentinelForge_colors_progress_bar() {
  local score=$1 label=$2 width=${3:-30}
  local filled=$((score * width / 100))
  local empty=$((width - filled))
  local filled_bar
  local empty_bar
  printf -v filled_bar '%*s' "$filled" ''
  printf -v empty_bar '%*s' "$empty" ''
  filled_bar=${filled_bar// /#}
  empty_bar=${empty_bar// /.}
  printf '[%s%s] %d%%  %s' "$filled_bar" "$empty_bar" "$score" "$label"
}

SentinelForge_colors_clear() {
  if [[ -n ${TERM:-} ]] && command -v tput >/dev/null 2>&1; then
    tput clear || printf '\033c'
  else
    printf '\033c'
  fi
}

SentinelForge_colors_header() {
  SentinelForge_colors_clear
  printf '%sSentinelForge | Maintainer: YrustPd | Repo: https://github.com/YrustPd/SentinelForge | License: AGPL-3.0%s\n' \
    "$SENTINELFORGE_COLOR_BOLD" "$SENTINELFORGE_COLOR_RESET"
  printf '%s================================================================================%s\n' \
    "$SENTINELFORGE_COLOR_MAGENTA" "$SENTINELFORGE_COLOR_RESET"
}

SentinelForge_colors_footer() {
  printf '%s--------------------------------------------------------------------------------%s\n' \
    "$SENTINELFORGE_COLOR_MAGENTA" "$SENTINELFORGE_COLOR_RESET"
  printf 'Project: https://github.com/YrustPd/SentinelForge\n'
}
