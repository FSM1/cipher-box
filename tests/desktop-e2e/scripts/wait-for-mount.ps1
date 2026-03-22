# wait-for-mount.ps1 -- Poll until the CipherBox FUSE mount point is available.
#
# Usage: .\wait-for-mount.ps1 [-MountPoint <path>]
#   -MountPoint  Path to check (default: $env:USERPROFILE\CipherBox)
#
# Environment:
#   MOUNT_TIMEOUT  Seconds to wait before failing (default: 90)

param(
    [string]$MountPoint = "$env:USERPROFILE\CipherBox"
)

$ErrorActionPreference = "Stop"

$Timeout = if ($env:MOUNT_TIMEOUT) { [int]$env:MOUNT_TIMEOUT } else { 90 }
$Interval = 2
$Elapsed = 0

Write-Host "Waiting for mount at $MountPoint (timeout: ${Timeout}s)..."

while ($Elapsed -lt $Timeout) {
    if (Test-Path -LiteralPath $MountPoint) {
        $item = Get-Item -LiteralPath $MountPoint -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            Write-Host "PASS: Mount detected at $MountPoint"
            exit 0
        }
    }

    Start-Sleep -Seconds $Interval
    $Elapsed += $Interval
}

Write-Host "FAIL: Mount not detected after ${Timeout}s"
exit 1
