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
# Shares one implementation with macOS/Linux (test-move-content.mjs); runs after
# cross-client-sync so the SDK dist it shells out to is already built.
Write-Host "--- Step 7: Move content re-encryption ---"
$MoveExitCode = 0
try {
    $env:TEST_SECRET = $TestSecret
    & node "$PSScriptRoot\test-move-content.mjs" --mount $MountPoint --api-url $ApiUrl
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

# ---- Summary ----
Write-Host "============================================"
Write-Host "  Summary"
Write-Host "============================================"
Write-Host "  Total failures: $TotalFail"
Write-Host "============================================"

exit $TotalFail
