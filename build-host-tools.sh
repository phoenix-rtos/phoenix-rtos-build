#!/usr/bin/env bash
# Shell script for building Phoenix-RTOS firmware
#
# Builder for Phoenix-RTOS host utils

b_log "Building host corelibs"
make -C "phoenix-rtos-corelibs" libptable

b_log "Building hostutils"
make -C "phoenix-rtos-hostutils" all
