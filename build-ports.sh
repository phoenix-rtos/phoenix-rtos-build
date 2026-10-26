#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS ports
#
# Copyright 2019, 2024, 2026 Phoenix Systems
# Author: Pawel Pisarczyk, Daniel Sawka, Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

function port_manager() {
	cd "${PREFIX_PROJECT}/phoenix-rtos-build/" || exit
	python3 ./port_manager.py "${@}"
}

[ -n "${PHOENIX_VER}" ] || b_die "PHOENIX_VER not set - run via build.sh"

b_log "Installing ports"

port_manager build "${PORTS_CONFIG}" "${PREFIX_PROJECT}/phoenix-rtos-ports"
