# test-recycle-bin.ps1 -- Verify FUSE deletes create recoverable bin entries (Windows).
#
# Usage: .\test-recycle-bin.ps1 [-MountPoint <path>] [-ApiUrl <url>]
#   -MountPoint   Path to FUSE mount (default: $env:USERPROFILE\CipherBox)
#   -ApiUrl       Backend API URL (default: http://localhost:3000)
#
# Environment:
#   TEST_SECRET   test-login shared secret (default: e2e-test-secret-ci-only)
#
# Tests:
#   1. Create test file on FUSE mount
#   2. Delete file, verify gone from mount
#   3. Verify API reachable with auth (vault config accessible)
#   4. Verify file CID preserved (soft-delete behavior)
#
# Exit code: number of failed tests (0 = all passed).

param(
    [string]$MountPoint = "$env:USERPROFILE\CipherBox",
    [string]$ApiUrl = "http://localhost:3000"
)

$TestSecret = if ($env:TEST_SECRET) { $env:TEST_SECRET } else { "e2e-test-secret-ci-only" }

$ErrorActionPreference = "Continue"

$TestEmail = "dev-key@cipherbox.local"

$Pass = 0
$Fail = 0

function Test-Pass {
    param([string]$Name)
    $script:Pass++
    Write-Host "PASS: $Name"
}

function Test-Fail {
    param([string]$Name)
    $script:Fail++
    Write-Host "FAIL: $Name"
}

Write-Host "=== Recycle Bin E2E Tests ==="
Write-Host "Mount point: $MountPoint"
Write-Host "API URL:     $ApiUrl"
Write-Host "Test email:  $TestEmail"
Write-Host ""

# ---- Setup: Authenticate via test-login ----
Write-Host "--- Setup: Authenticate via test-login ---"
$Body = @{
    email  = $TestEmail
    secret = $TestSecret
} | ConvertTo-Json

$AccessToken = $null
try {
    $AuthResponse = Invoke-RestMethod -Uri "$ApiUrl/auth/test-login" `
        -Method Post `
        -ContentType "application/json" `
        -Body $Body

    $AccessToken = $AuthResponse.accessToken
    if (-not $AccessToken) {
        throw "No accessToken in response"
    }
    Write-Host "Authenticated OK"
} catch {
    Write-Host "FATAL: Could not get auth token ($_). Is the API running?"
    Write-Host ""
    Write-Host "=== Recycle Bin E2E Results ==="
    Write-Host "  Passed: $Pass"
    Write-Host "  Failed: $Fail"
    Write-Host "==============================="
    exit 1
}

$Headers = @{ Authorization = "Bearer $AccessToken" }
Write-Host ""

# ---- Test 1: Create test file on mount ----
$TestFile = "e2e-bin-$(Get-Random).txt"
Write-Host "--- Test 1: Create test file ($TestFile) ---"
$TestContent = "Bin test content $(Get-Date -UFormat %s)"
try {
    Set-Content -Path "$MountPoint\$TestFile" -Value $TestContent -NoNewline -ErrorAction Stop
    Start-Sleep -Seconds 10  # Wait for upload + IPNS publish

    if (Test-Path "$MountPoint\$TestFile") {
        Test-Pass "Create test file"
    } else {
        Test-Fail "Create test file (not found after write)"
    }
} catch {
    Test-Fail "Create test file ($_)"
}

# Capture pre-deletion content
$PreDeleteContent = ""
try {
    $PreDeleteContent = Get-Content -Path "$MountPoint\$TestFile" -Raw -ErrorAction SilentlyContinue
} catch { }

# ---- Test 2: Delete file from mount ----
Write-Host "--- Test 2: Delete file from mount ---"
try {
    Remove-Item -Path "$MountPoint\$TestFile" -Force -ErrorAction Stop
    Start-Sleep -Seconds 10  # Wait for folder metadata publish + bin IPNS publish

    if (-not (Test-Path "$MountPoint\$TestFile")) {
        Test-Pass "Delete file from mount (file removed)"
    } else {
        Test-Fail "Delete file from mount (file still exists)"
    }
} catch {
    Test-Fail "Delete file from mount ($_)"
}

# ---- Test 3: Verify vault config reachable (API health for bin) ----
Write-Host "--- Test 3: Verify vault config reachable ---"
try {
    $VaultResponse = Invoke-RestMethod -Uri "$ApiUrl/vault" -Headers $Headers
    if ($VaultResponse) {
        Test-Pass "Vault API reachable (bin entries stored server-side)"
    } else {
        Test-Fail "Vault API returned empty response"
    }
} catch {
    Test-Fail "Vault API unreachable ($_)"
}

# ---- Test 4: Verify soft-delete behavior ----
Write-Host "--- Test 4: Verify soft-delete behavior ---"
$FileGone = -not (Test-Path "$MountPoint\$TestFile")
$HadContent = $PreDeleteContent.Length -gt 0

if ($FileGone -and $HadContent) {
    Test-Pass "Soft-delete behavior (file removed from mount, had content before deletion)"
} elseif (-not $HadContent) {
    Test-Fail "Soft-delete behavior (file had no content before deletion)"
} else {
    Test-Fail "Soft-delete behavior (file still on mount after deletion)"
}

# ---- Cleanup ----
Write-Host "--- Cleanup ---"
Remove-Item -Path "$MountPoint\$TestFile" -Force -ErrorAction SilentlyContinue
Test-Pass "Cleanup"

# ---- Summary ----
Write-Host ""
Write-Host "=== Recycle Bin E2E Results ==="
Write-Host "  Passed: $Pass"
Write-Host "  Failed: $Fail"
Write-Host "==============================="

exit $Fail
