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
    Write-Host "FUSE test script error: $($_.Exception.Message)"
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
    $env:TEST_SECRET = $TestSecret
    & "$PSScriptRoot\test-round-trip.ps1" -MountPoint $MountPoint -ApiUrl $ApiUrl
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

# ---- Step 4: Conflict detection ----
Write-Host "--- Step 4: Conflict detection ---"
$ConflictExitCode = 0
try {
    $env:TEST_SECRET = $TestSecret
    & "$PSScriptRoot\test-conflict-detection.ps1" -MountPoint $MountPoint -ApiUrl $ApiUrl
    $ConflictExitCode = $LASTEXITCODE
} catch {
    Write-Host "Conflict detection script error: $($_.Exception.Message)"
    $ConflictExitCode = 1
}

if ($ConflictExitCode -eq 0) {
    Write-Host "Conflict detection: ALL PASSED"
} else {
    Write-Host "Conflict detection: $ConflictExitCode FAILURE(S)"
    $TotalFail += $ConflictExitCode
}
Write-Host ""

# ---- Step 5: Recycle bin ----
Write-Host "--- Step 5: Recycle bin ---"
$BinExitCode = 0
try {
    $env:TEST_SECRET = $TestSecret
    & "$PSScriptRoot\test-recycle-bin.ps1" -MountPoint $MountPoint -ApiUrl $ApiUrl
    $BinExitCode = $LASTEXITCODE
} catch {
    Write-Host "Recycle bin script error: $($_.Exception.Message)"
    $BinExitCode = 1
}

if ($BinExitCode -eq 0) {
    Write-Host "Recycle bin: ALL PASSED"
} else {
    Write-Host "Recycle bin: $BinExitCode FAILURE(S)"
    $TotalFail += $BinExitCode
}
Write-Host ""

# ---- Step 6: Cross-client sync ----
Write-Host "--- Step 6: Cross-client sync ---"
$SyncExitCode = 0
try {
    $env:TEST_SECRET = $TestSecret
    & "$PSScriptRoot\test-cross-client-sync.ps1" -MountPoint $MountPoint -ApiUrl $ApiUrl
    $SyncExitCode = $LASTEXITCODE
} catch {
    Write-Host "Cross-client sync script error: $($_.Exception.Message)"
    $SyncExitCode = 1
}

if ($SyncExitCode -eq 0) {
    Write-Host "Cross-client sync: ALL PASSED"
} else {
    Write-Host "Cross-client sync: $SyncExitCode FAILURE(S)"
    $TotalFail += $SyncExitCode
}
Write-Host ""

# ---- Step 7: Move content re-encryption (cross-platform) ----
# Shares one implementation with macOS/Linux (test-move-content.ts); runs after
# cross-client-sync so the SDK dist it shells out to is already built.
Write-Host "--- Step 7: Move content re-encryption ---"
$MoveExitCode = 0
try {
    $env:TEST_SECRET = $TestSecret
    & pnpm exec tsx "$PSScriptRoot\test-move-content.ts" --mount $MountPoint --api-url $ApiUrl
    $MoveExitCode = $LASTEXITCODE
} catch {
    Write-Host "Move content script error: $($_.Exception.Message)"
    $MoveExitCode = 1
}

if ($MoveExitCode -eq 0) {
    Write-Host "Move content: PASSED"
} else {
    Write-Host "Move content: FAILED"
    $TotalFail += $MoveExitCode
}
Write-Host ""

# ---- Step 8: Shared scope-exit rotation acceptance (D-16) ----
# Real-mount smoke for the shared-scope-exit rotation live-wiring (Phase 70.1
# SC#8), shared with macOS/Linux (shared-scope-exit-rotation.mts). Invoked via
# node + tsx's JS CLI entry (NOT the .bin/tsx shim) per project convention for
# .mts helpers. Exercises the WinFsp rotation path on Windows.
#
# Phase 74 (74-07) extended this SAME script with three more legs, all run
# by this one invocation: Part C proves a depth>=2 scope-exit refreshes
# every rotated node's key (SC1, 74-03) and distinguishes a retained
# recipient (re-minted, SC2, 74-05) from a revoked one; Part D proves an
# overwrite-rename against a covered destination triggers the scope-exit
# gate -- on Windows this is the authoritative runtime proof for 74-06's
# WinFsp handle_rename destination scope-exit gate fix (SC3), the runtime
# counterpart to that plan's Cargo Check & Test (Windows) unit tests.
Write-Host "--- Step 8: Shared scope-exit rotation acceptance (D-16) ---"
$RepoRoot = (Resolve-Path "$PSScriptRoot\..\..\..").Path
$RotationExitCode = 0
try {
    $env:TEST_SECRET = $TestSecret
    & node "$RepoRoot\node_modules\tsx\dist\cli.mjs" "$PSScriptRoot\shared-scope-exit-rotation.mts" --mount $MountPoint --api-url $ApiUrl
    $RotationExitCode = $LASTEXITCODE
} catch {
    Write-Host "Shared scope-exit rotation script error: $($_.Exception.Message)"
    $RotationExitCode = 1
}

if ($RotationExitCode -eq 0) {
    Write-Host "Shared scope-exit rotation: PASSED"
} else {
    Write-Host "Shared scope-exit rotation: FAILED"
    $TotalFail += $RotationExitCode
}
Write-Host ""

# ---- Summary ----
Write-Host "============================================"
Write-Host "  Summary"
Write-Host "============================================"
Write-Host "  Total failures: $TotalFail"
Write-Host "============================================"

exit $TotalFail
