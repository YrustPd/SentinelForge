#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
IFS=$'\n\t'

: "${SENTINELFORGE_APP_ROOT:?SENTINELFORGE_APP_ROOT must be defined}"

SENTINELFORGE_SRC_ROOT="${SENTINELFORGE_APP_ROOT}/src"
SENTINELFORGE_ETC_ROOT="${SENTINELFORGE_APP_ROOT}/etc"
SENTINELFORGE_SHARE_ROOT="${SENTINELFORGE_APP_ROOT}/share"

SENTINELFORGE_VERSION_FILE="${SENTINELFORGE_APP_ROOT}/VERSION"
if [[ ! -f "${SENTINELFORGE_VERSION_FILE}" && -f "/usr/local/share/sentinelforge/VERSION" ]]; then
  SENTINELFORGE_VERSION_FILE="/usr/local/share/sentinelforge/VERSION"
fi

if [[ -f "${SENTINELFORGE_VERSION_FILE}" ]]; then
  SENTINELFORGE_VERSION="$(tr -d '\n' <"${SENTINELFORGE_VERSION_FILE}")"
else
  SENTINELFORGE_VERSION="0.0.0-unknown"
fi

SENTINELFORGE_LOG_FILE=${SENTINELFORGE_LOG_FILE:-/var/log/sentinelforge.log}
SENTINELFORGE_BACKUP_DIR=${SENTINELFORGE_BACKUP_DIR:-/etc/sentinelforge/backups}
SENTINELFORGE_CONFIG_PATH=${SENTINELFORGE_CONFIG_PATH:-/etc/sentinelforge.conf}
SENTINELFORGE_DEFAULT_CONFIG="${SENTINELFORGE_ETC_ROOT}/sentinelforge.conf"

if [[ -f "${SENTINELFORGE_DEFAULT_CONFIG}" ]]; then
  # shellcheck disable=SC1091
  source "${SENTINELFORGE_DEFAULT_CONFIG}"
fi
if [[ -f "${SENTINELFORGE_CONFIG_PATH}" ]]; then
  # shellcheck disable=SC1091
  source "${SENTINELFORGE_CONFIG_PATH}"
fi

SentinelForge_internal_source_module() {
  local module=$1
  local path="${SENTINELFORGE_SRC_ROOT}/${module}"
  if [[ ! -f "${path}" ]]; then
    printf 'SentinelForge: missing module %s\n' "${module}" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  source "${path}"
}

SentinelForge_internal_source_module "core/colors.sh"
SentinelForge_internal_source_module "core/ui.sh"
SentinelForge_internal_source_module "core/utils.sh"
SentinelForge_internal_source_module "core/detect.sh"
SentinelForge_internal_source_module "core/score.sh"
SentinelForge_internal_source_module "features/updates.sh"
SentinelForge_internal_source_module "features/fail2ban.sh"
SentinelForge_internal_source_module "features/sysctl.sh"
SentinelForge_internal_source_module "features/firewall.sh"
SentinelForge_internal_source_module "features/ddos.sh"
SentinelForge_internal_source_module "features/ssh.sh"
SentinelForge_internal_source_module "features/dashboard.sh"

SentinelForge_utils_setup_traps
SentinelForge_colors_init
SENTINELFORGE_MENU_BACKTITLE="SentinelForge ${SENTINELFORGE_VERSION} | Maintainer: YrustPd | Repo: https://github.com/YrustPd/SentinelForge"

SentinelForge::main() {
  local subcommand=${1:-}
  SentinelForge_utils_info "Launching SentinelForge (subcommand: ${subcommand:-dashboard})"
  case "${subcommand}" in
    --version|-V)
      printf 'SentinelForge %s\nMaintainer: YrustPd\nRepo: https://github.com/YrustPd/SentinelForge\n' "${SENTINELFORGE_VERSION}"
      return 0
      ;;
    --doctor)
      local doctor_candidates=(
        "${SENTINELFORGE_APP_ROOT}/scripts/doctor.sh"
        "${SENTINELFORGE_SHARE_ROOT}/../scripts/doctor.sh"
      )
      local doctor
      for doctor in "${doctor_candidates[@]}"; do
        if [[ -x "${doctor}" ]]; then
          "${doctor}"
          return 0
        elif [[ -f "${doctor}" ]]; then
          bash "${doctor}"
          return 0
        fi
      done
      printf 'SentinelForge doctor utility unavailable. Ensure scripts/doctor.sh is installed.\n' >&2
      return 1
      ;;
    --help|-h)
      cat <<'USAGE'
SentinelForge — YrustPd (AGPL-3.0)
Usage: sentinelforge [--version] [--doctor]
Run without arguments to launch the interactive dashboard.
USAGE
      return 0
      ;;
    --install|--uninstall|--reinstall)
      printf 'Installation flags are handled by scripts/install.sh.\n' >&2
      return 1
      ;;
    "")
      SentinelForge_dashboard_run
      ;;
    *)
      printf 'SentinelForge: unknown option %s\n' "${subcommand}" >&2
      return 1
      ;;
  esac
}
