# test-conflict-detection.ps1 -- Verify FUSE conflict detection and re-sync behavior (Windows).
#
# Usage: .\test-conflict-detection.ps1 [-MountPoint <path>] [-ApiUrl <url>]
#   -MountPoint   Path to FUSE mount (default: $env:USERPROFILE\CipherBox)
#   -ApiUrl       Backend API URL (default: http://localhost:3000)
#
# Environment:
#   TEST_SECRET   Shared secret for test-login (default: e2e-test-secret-ci-only)
#
# These tests verify that when the server-side IPNS sequence number is bumped
# (simulating another device publishing), the desktop detects the 409 conflict,
# re-syncs, and retries -- resulting in all files/directories being accessible.
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

Write-Host "=== Conflict Detection Tests ==="
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
} catch {
    Write-Host "FATAL: Authentication failed ($_)"
}

if (-not $AccessToken) {
    Write-Host "FATAL: Cannot proceed without authentication."
    Write-Host ""
    Write-Host "=== Conflict Detection Results ==="
    Write-Host "  Passed: $Pass"
    Write-Host "  Failed: $Fail"
    Write-Host "=================================="
    exit 1
}
Write-Host "  Authenticated successfully"

$Headers = @{ Authorization = "Bearer $AccessToken" }

# ---- Setup: Get root IPNS name from vault ----
Write-Host "--- Setup: Get root IPNS name from vault ---"
$RootIpns = $null
try {
    $VaultResponse = Invoke-RestMethod -Uri "$ApiUrl/vault" -Headers $Headers
    $RootIpns = $VaultResponse.rootIpnsName
} catch {
    Write-Host "FATAL: Failed to retrieve vault ($_)"
}

if (-not $RootIpns) {
    Write-Host "FATAL: No rootIpnsName found in vault -- cannot test conflict detection without a published vault."
    Write-Host "       Ensure the desktop app has made at least one FUSE write before running this test."
    Write-Host ""
    Write-Host "=== Conflict Detection Results ==="
    Write-Host "  Passed: $Pass"
    Write-Host "  Failed: $Fail"
    Write-Host "=================================="
    exit 1
}
Write-Host "  Root IPNS: $RootIpns"
Write-Host ""

# ---- Helper: Invoke-BumpServerSequence ----
# Advances the vault's root IPNS sequence with a REAL, validly-signed record.
# The server is signature-gated (it rejects records whose Ed25519 SignatureV2
# does not verify against the name's key), so a dummy unsigned record can no
# longer fake a bump. bump-ipns-sequence.ts derives the deterministic vault IPNS
# keypair and republishes the current root metadata UNCHANGED at sequence+1 --
# exactly what a legitimate second device does -- making the desktop's cached
# sequence stale.
function Invoke-BumpServerSequence {
    param([string]$IpnsName)  # informational; the helper bumps the vault root via /vault

    $BumpScript = Join-Path $PSScriptRoot "bump-ipns-sequence.ts"
    $env:TEST_SECRET = $TestSecret
    & pnpm exec tsx $BumpScript --api-url $ApiUrl --email $TestEmail
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to bump server sequence for ${IpnsName} (exit $LASTEXITCODE)"
    }
}

# ---- Test 1: Write file via FUSE, bump server seq, write another file -> both readable ----
Write-Host "--- Test 1: Write file, bump server sequence, write another file -> both readable ---"

# Step 1: Write first file and wait for FUSE debounce + publish
try {
    Set-Content -Path "$MountPoint\conflict-test-1.txt" -Value "file-before-bump" -NoNewline -ErrorAction Stop
    Write-Host "  Wrote conflict-test-1.txt, waiting 8s for FUSE publish..."
    Start-Sleep -Seconds 8
} catch {
    Write-Host "  WARNING: Failed to write conflict-test-1.txt ($_)"
}

# Step 2: Bump server sequence to make desktop's local sequence stale
Write-Host "  Bumping server sequence..."
Invoke-BumpServerSequence -IpnsName $RootIpns

# Step 3: Write second file -- the FUSE publish will get a 409, re-sync, and retry
try {
    Set-Content -Path "$MountPoint\conflict-test-2.txt" -Value "file-after-bump" -NoNewline -ErrorAction Stop
    Write-Host "  Wrote conflict-test-2.txt, waiting 15s for conflict resolution + retry..."
    Start-Sleep -Seconds 15
} catch {
    Write-Host "  WARNING: Failed to write conflict-test-2.txt ($_)"
}

# Step 4: Verify both files are readable
$Content1 = $null
$Content2 = $null
try { $Content1 = (Get-Content -Path "$MountPoint\conflict-test-1.txt" -Raw -ErrorAction Stop).Trim() } catch {}
try { $Content2 = (Get-Content -Path "$MountPoint\conflict-test-2.txt" -Raw -ErrorAction Stop).Trim() } catch {}

if ($Content1 -eq "file-before-bump" -and $Content2 -eq "file-after-bump") {
    Test-Pass "Write file conflict: both files readable after re-sync and retry"
} elseif ($Content1 -ne "file-before-bump") {
    Test-Fail "Write file conflict: conflict-test-1.txt has unexpected content (got: '$Content1')"
} else {
    Test-Fail "Write file conflict: conflict-test-2.txt has unexpected content (got: '$Content2')"
}

# ---- Test 2: Create directory via FUSE, bump server seq, create file in dir -> both accessible ----
Write-Host "--- Test 2: Create directory, bump server sequence, create file in dir -> both accessible ---"

# Step 1: Create directory and wait for FUSE publish
try {
    New-Item -ItemType Directory -Path "$MountPoint\conflict-dir" -Force -ErrorAction Stop | Out-Null
    Write-Host "  Created conflict-dir, waiting 8s for FUSE publish..."
    Start-Sleep -Seconds 8
} catch {
    Write-Host "  WARNING: Failed to create conflict-dir ($_)"
}

# Step 2: Bump server sequence
Write-Host "  Bumping server sequence..."
Invoke-BumpServerSequence -IpnsName $RootIpns

# Step 3: Write file in directory -- the mkdir publish will hit 409, re-sync, retry
try {
    Set-Content -Path "$MountPoint\conflict-dir\nested.txt" -Value "nested-conflict-file" -NoNewline -ErrorAction Stop
    Write-Host "  Writing conflict-dir\nested.txt, waiting 15s for conflict resolution + retry..."
    Start-Sleep -Seconds 15
} catch {
    Write-Host "  WARNING: Failed to write conflict-dir\nested.txt ($_)"
}

# Step 4: Verify directory exists and file is readable
$DirExists = Test-Path "$MountPoint\conflict-dir" -PathType Container
$Nested = $null
try { $Nested = (Get-Content -Path "$MountPoint\conflict-dir\nested.txt" -Raw -ErrorAction Stop).Trim() } catch {}

if ($DirExists -and $Nested -eq "nested-conflict-file") {
    Test-Pass "Directory conflict: dir exists and nested file readable after re-sync and retry"
} elseif (-not $DirExists) {
    Test-Fail "Directory conflict: conflict-dir does not exist after re-sync"
} else {
    Test-Fail "Directory conflict: nested.txt has unexpected content (got: '$Nested')"
}

# ---- Cleanup ----
# Wrap in try/catch: on WinFSP mounts, Remove-Item can throw terminating
# .NET exceptions ("The system cannot find the file specified") that
# -ErrorAction SilentlyContinue does not suppress.
Write-Host "--- Cleanup ---"
try { Remove-Item -Path "$MountPoint\conflict-test-1.txt" -Force -ErrorAction SilentlyContinue } catch {}
try { Remove-Item -Path "$MountPoint\conflict-test-2.txt" -Force -ErrorAction SilentlyContinue } catch {}
try { Remove-Item -Path "$MountPoint\conflict-dir" -Recurse -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Seconds 3

# ---- Summary ----
Write-Host ""
Write-Host "=== Conflict Detection Results ==="
Write-Host "  Passed: $Pass"
Write-Host "  Failed: $Fail"
Write-Host "=================================="

exit $Fail
