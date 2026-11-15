#!/bin/bash
# Builds build/novpn and build/tests, then runs the tests.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
swiftc -O -o build/novpn Sources/*.swift
swiftc -o build/tests Sources/Policy.swift Sources/Status.swift Sources/System.swift Sources/ShellHook.swift Tests/main.swift
build/tests
