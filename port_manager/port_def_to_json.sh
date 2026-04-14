#!/usr/bin/env bash
#
# Port management
#
# port.def.sh to JSON loading script (invoked by port_manager.py)
#
# Copyright 2026 Phoenix Systems
# Author: Adam Greloch
#
# SPDX-License-Identifier: BSD-3-Clause
#

def_path="${1?}"
source_dir="$(dirname "${BASH_SOURCE[0]}")"

source "${source_dir}/port_internal.subr"
load_port_def "${def_path}"

# ports_api=1
: "${ports_api?}"

ports_apis=(1)

for api in "${ports_apis[@]}"; do
	if [[ "$ports_api" == "$api" ]]; then
		found=true
		break
	fi
done

if [ ! "${found}" ]; then
	b_die "bad ports_api: ${ports_api} (supported: ${ports_apis[*]})"
fi

: "${name?}"
: "${version?}"
: "${desc?}"

if [ -z "${source}" ]; then
	# if tarball source not provided, expect git rev/source
	: "${git_rev?}"
	: "${git_source?}"
else
	: "${archive_filename?}"

	if ((${#archive_filename[@]} > 2)); then
		b_die "archive_filename must have at most 2 elements, got ${#archive_filename[@]}"
	fi
fi

: "${sha256?}"
: "${size?}"

# must follow SPDX:
#  https://spdx.github.io/spdx-spec/v3.0.1/annexes/spdx-license-expressions/
#  https://spdx.org/licenses/
: "${license?}"
: "${license_file?}"

# e.g. supports="phoenix>=3.4"
: "${supports?}"

: "${src_path?}"
: "${conflicts?}"
: "${depends?}"

# TODO: add host dependencies fields?

[[ $(type -t p_prepare) == function ]] || b_die "p_prepare undefined"
[[ $(type -t p_build) == function ]] || b_die "p_build undefined"

# shellcheck disable=2154 # variables loaded from port.def.sh
jq -n \
	--arg namever "${name}-${version}" \
	--arg requires "${depends}" \
	--arg optional "${optional}" \
	--arg conflicts "${conflicts}" \
	--arg iuse "${iuse}" \
	--arg supports "${supports}" \
	--arg desc "${desc}" \
	'{
    namever: $namever,
    requires: $requires,
    optional: $optional,
    conflicts: $conflicts,
    iuse: $iuse,
    supports: $supports,
    desc: $desc,
  }'
