#!/usr/bin/env bash

echo "## Port definitions"
echo ""
echo "| Name | Version | Requirements | Conflicts | Flags | Definition |"
echo "|------|---------|--------------|-----------|-------|------------|"

jq -r '
  to_entries[] as $pkg |
  $pkg.value | to_entries[] |
  "| \($pkg.key) | \(.key) | \(.value.requirements | join(", ")) | \(.value.conflicts | join(", ")) | \(.value.iuse | join(", ")) | \(.value.port_def_path) |"
' "${1?}"
