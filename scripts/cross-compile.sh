#!/bin/bash

# This script cross-compiles the ArchGuardian application for multiple platforms.

# Exit immediately if a command exits with a non-zero status.
set -e

# Define the output directory for the binaries
OUTPUT_DIR="build"

# Define the main package path for the application.
PACKAGE_PATH="./cmd/archguardian"

# Get the project version from the latest git tag, or default to v0.1.0
VERSION=$(git describe --tags --abbrev=0 --always --dirty 2>/dev/null || echo "v0.1.0")

LD_FLAGS="-s -w -X main.Version=${VERSION}"

# Create the output directory if it doesn't exist
echo "Creating build directory: ${OUTPUT_DIR}"
mkdir -p ${OUTPUT_DIR}

# --- Compile for Linux (amd64) ---
echo "Compiling for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="${LD_FLAGS}" -o ${OUTPUT_DIR}/archguardian-linux-amd64 ${PACKAGE_PATH}

# --- Compile for Windows (amd64) ---
echo "Compiling for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="${LD_FLAGS}" -o ${OUTPUT_DIR}/archguardian-windows-amd64.exe ${PACKAGE_PATH}

# --- Compile for macOS (Intel/amd64) ---
echo "Compiling for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="${LD_FLAGS}" -o ${OUTPUT_DIR}/archguardian-darwin-amd64 ${PACKAGE_PATH}

# --- Compile for macOS (Apple Silicon/arm64) ---
echo "Compiling for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="${LD_FLAGS}" -o ${OUTPUT_DIR}/archguardian-darwin-arm64 ${PACKAGE_PATH}

echo "✅ Cross-compilation complete. Binaries are in the '${OUTPUT_DIR}' directory."
ls -l ${OUTPUT_DIR}