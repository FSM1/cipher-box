#!/usr/bin/env bash
set -euo pipefail

# wait-for-mount.sh -- Poll until the CipherBox FUSE mount point is available.
#
# Usage: ./wait-for-mount.sh [mount-point]
#   mount-point  Path to check (default: $HOME/CipherBox)
#
# Environment:
#   MOUNT_TIMEOUT  Seconds to wait before failing (default: 90)

MOUNT_POINT="${1:-$HOME/CipherBox}"
TIMEOUT="${MOUNT_TIMEOUT:-90}"
INTERVAL=2
ELAPSED=0

echo "Waiting for mount at $MOUNT_POINT (timeout: ${TIMEOUT}s)..."

while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
  # Check that the mount point directory exists AND that something is mounted there.
  # macOS (FUSE-T SMB backend) shows "smbfs" in mount output; Linux shows "fuse".
  # We grep for the mount path itself for cross-platform consistency.
  if [ -d "$MOUNT_POINT" ] && mount | grep -q "$MOUNT_POINT"; then
    echo "PASS: Mount detected at $MOUNT_POINT"
    exit 0
  fi

  sleep "$INTERVAL"
  ELAPSED=$((ELAPSED + INTERVAL))
done

echo "FAIL: Mount not detected after ${TIMEOUT}s"
exit 1
