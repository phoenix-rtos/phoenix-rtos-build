#!/bin/bash
#
# Port management
#
# Port cleaning script (invoked by port_manager.py)
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

set -e

def_path="${1?}"

source "$(dirname "${BASH_SOURCE[0]}")/port_internal.subr"
load_port_def "${def_path}"

# shellcheck disable=2154 # name, version loaded from port.def.sh
PREFIX_PORT_BUILD="${PREFIX_BUILD?}/port-sources/${name}-${version}"

echo "CLEAN: ${name}-${version}"

if [ -d "${PREFIX_PORT_BUILD}" ]; then
	rm -rf "${PREFIX_PORT_BUILD}"
fi
