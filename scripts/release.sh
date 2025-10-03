#!/bin/bash

# This script uploads the cross-compiled binaries to R2 cloud storage.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
# Define the R2 remote name and bucket name.
# Replace 'r2' with your configured rclone remote name.
# Replace 'archguardian-releases' with your R2 bucket name.
RCLONE_REMOTE="incline"
RCLONE_BUCKET="archguardian"

# Define the local build directory
BUILD_DIR="build"

# --- Pre-flight Check ---
# Check if rclone is installed
if ! command -v rclone &> /dev/null
then
    echo "❌ rclone could not be found. Please install and configure it first."
    echo "   See: https://rclone.org/install/"
    exit 1
fi

# Check if build directory exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "❌ Build directory '${BUILD_DIR}' not found. Please run 'make cross-compile' first."
    exit 1
fi

# --- Upload Binaries ---
echo "🚀 Starting release upload to R2 bucket: ${RCLONE_BUCKET}"

# Upload Windows binary
echo "  -> Uploading Windows binary..."
rclone copy "${BUILD_DIR}/archguardian-windows-amd64.exe" "${RCLONE_REMOTE}:${RCLONE_BUCKET}/windows/"

# Upload Linux binary
echo "  -> Uploading Linux binary..."
rclone copy "${BUILD_DIR}/archguardian-linux-amd64" "${RCLONE_REMOTE}:${RCLONE_BUCKET}/linux/"

# Upload macOS binaries
echo "  -> Uploading macOS binaries..."
rclone copy "${BUILD_DIR}/archguardian-darwin-amd64" "${RCLONE_REMOTE}:${RCLONE_BUCKET}/mac/"
rclone copy "${BUILD_DIR}/archguardian-darwin-arm64" "${RCLONE_REMOTE}:${RCLONE_BUCKET}/mac/"

echo "✅ Upload complete. Verifying files in R2 bucket..."
rclone ls "${RCLONE_REMOTE}:${RCLONE_BUCKET}/"
echo "🎉 Release process finished successfully."