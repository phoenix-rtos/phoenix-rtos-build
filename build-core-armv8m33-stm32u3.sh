#!/usr/bin/env bash
#
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS Loader on STM32U3
#
# Copyright 2018-2024 Phoenix Systems
# Copyright 2026 Apator Metrix
# Author: Kaja Swat, Aleksander Kaminski, Pawel Pisarczyk, Mateusz Karcz
#

# fail immediately if any of the commands fails
set -e

b_log "Building phoenix-rtos-kernel"
make -C "phoenix-rtos-kernel" install-headers
