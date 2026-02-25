#!/bin/bash
#
# Port management
#
# Port building script (invoked by port_manager.py)
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

set -ex

def_dir="${1?}"
log_file="${2?}"

exec > >(tee -a "${log_file}") 2>&1

source "$(dirname "${BASH_SOURCE[0]}")/port_internal.subr"

load_port_def "${def_dir}"

unset_internal_env

# shellcheck disable=2154 # name, version loaded from port.def.sh
echo "$(date +%FT%T): BUILD: ${name}-${version}"

export PREFIX_H="${PREFIX_PORT_INSTALL}/include"
export PREFIX_A="${PREFIX_PORT_INSTALL}/lib"

# TODO: p_clean() ?
# [[ $(type -t p_common) == function ]] && p_common # definition is optional

p_build

if [ "${PORT_BUILD_TESTS}" = "y" ]; then
	[[ $(type -t p_build_test) == function ]] || b_die "\`tests: true\` but p_build_test undefined"
	p_build_test
fi
