#!/usr/bin/env bats
# SPDX-License-Identifier: AGPL-3.0-only

setup() {
  cd "$(dirname "$BATS_TEST_FILENAME")/../.."
}

@test "VERSION file has semantic version" {
  run cat VERSION
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "sentinelforge --version prints metadata" {
  run bin/sentinelforge --version
  [ "$status" -eq 0 ]
  [[ "$output" == *"SentinelForge"* ]]
  [[ "$output" == *"Maintainer"* ]]
}
