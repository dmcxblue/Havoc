#!/bin/bash
# Project checks. The workflow gate runs this once per change set before a turn
# may end, and /workflow:review reuses the result. Exit non-zero on any failure.
#
# This repo has no test suite (see CLAUDE.md: `go test ./...` runs nothing).
# The client is a heavy Qt/CMake build and the Demon cross-compiles at listener
# start, so neither belongs in a per-turn gate. The fast, meaningful check is
# that the Go teamserver — the actively developed component — compiles and vets.
set -e

cd "$(dirname "$0")/../teamserver"
GO111MODULE=on go build ./...
GO111MODULE=on go vet ./...
