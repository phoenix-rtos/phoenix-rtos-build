#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS ports
#
# Copyright 2019, 2024, 2026 Phoenix Systems
# Author: Pawel Pisarczyk, Daniel Sawka, Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

PORT_MANAGER_FLAGS=(
)

function port_manager() {
  cd "${PREFIX_PROJECT}/phoenix-rtos-build/" || exit
  python3 -m "port_manager.main" "${PORT_MANAGER_FLAGS[@]}" "${@}"
}

if [ "$RAW_LOG" != 1 ]; then
  PORT_MANAGER_FLAGS+=("-r")
fi

DUMMY_VERSION="v3.3.1-0-g"
GIT_DESC="$(cd "./phoenix-rtos-build" && git describe --tags --abbrev=0 --match "v[[:digit:]].[[:digit:]]*.[[:digit:]]*" 2> /dev/null || echo "${DUMMY_VERSION}")"

b_log "Installing ports"

PHOENIX_VER="${GIT_DESC}" port_manager build "${PORTS_CONFIG}" "${PREFIX_PROJECT}/phoenix-rtos-ports"
