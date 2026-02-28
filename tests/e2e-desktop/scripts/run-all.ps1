# run-all.ps1 -- Orchestrate the full desktop E2E test suite (Windows).
#
# Runs wait-for-mount, FUSE file I/O tests, and API round-trip tests.
# Reports an aggregate pass/fail summary and exits with the total failure count.
#
# Environment:
#   MOUNT_POINT   Path to FUSE mount (default: $env:USERPROFILE\CipherBox)
#   API_URL       Backend API URL (default: http://localhost:3000)
#   TEST_SECRET   test-login shared secret (default: e2e-test-secret-ci-only)

$ErrorActionPreference = "Stop"

$MountPoint = if ($env:MOUNT_POINT) { $env:MOUNT_POINT } else { "$env:USERPROFILE\CipherBox" }
$ApiUrl = if ($env:API_URL) { $env:API_URL } else { "http://localhost:3000" }
$TestSecret = if ($env:TEST_SECRET) { $env:TEST_SECRET } else { "e2e-test-secret-ci-only" }

$TotalFail = 0

Write-Host "============================================"
Write-Host "  CipherBox Desktop E2E Test Suite"
Write-Host "============================================"
Write-Host ""
Write-Host "Mount point: $MountPoint"
Write-Host "API URL:     $ApiUrl"
Write-Host ""

# ---- Step 1: Wait for mount ----
Write-Host "--- Step 1: Wait for mount ---"
try {
    & "$PSScriptRoot\wait-for-mount.ps1" -MountPoint $MountPoint
} catch {
    Write-Host "FATAL: Mount not available. Cannot continue."
    exit 1
}
Write-Host ""

# ---- Step 2: FUSE file operations ----
Write-Host "--- Step 2: FUSE file operations ---"
$FuseExitCode = 0
try {
    & "$PSScriptRoot\test-fuse-operations.ps1" -MountPoint $MountPoint
    $FuseExitCode = $LASTEXITCODE
} catch {
    $FuseExitCode = 1
}

if ($FuseExitCode -eq 0) {
    Write-Host "FUSE operations: ALL PASSED"
} else {
    Write-Host "FUSE operations: $FuseExitCode FAILURE(S)"
    $TotalFail += $FuseExitCode
}
Write-Host ""

# ---- Step 3: API round-trip ----
Write-Host "--- Step 3: API round-trip ---"
$RtExitCode = 0
try {
    & "$PSScriptRoot\test-round-trip.ps1" -MountPoint $MountPoint -ApiUrl $ApiUrl -TestSecret $TestSecret
    $RtExitCode = $LASTEXITCODE
} catch {
    $RtExitCode = 1
}

if ($RtExitCode -eq 0) {
    Write-Host "API round-trip: ALL PASSED"
} else {
    Write-Host "API round-trip: $RtExitCode FAILURE(S)"
    $TotalFail += $RtExitCode
}
Write-Host ""

# ---- Summary ----
Write-Host "============================================"
Write-Host "  Summary"
Write-Host "============================================"
Write-Host "  Total failures: $TotalFail"
Write-Host "============================================"

exit $TotalFail
