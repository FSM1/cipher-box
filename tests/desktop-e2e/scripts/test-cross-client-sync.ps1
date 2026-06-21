# test-cross-client-sync.ps1 -- Verify FUSE mount picks up file edits made via SDK (Windows).
#
# Usage: .\test-cross-client-sync.ps1 [-MountPoint <path>] [-ApiUrl <url>]
#   -MountPoint   Path to FUSE mount (default: $env:USERPROFILE\CipherBox)
#   -ApiUrl       Backend API URL (default: http://localhost:3000)
#
# Environment:
#   TEST_SECRET   Shared secret for test-login (default: e2e-test-secret-ci-only)
#
# This test exercises the cross-client sync path:
# 1. Write a file via the FUSE mount (desktop client)
# 2. Edit the file via the SDK (simulating a web UI edit)
# 3. Wait for the FUSE mount to detect the change (IPNS polling)
# 4. Read the file from the FUSE mount and verify updated content
#
# Exit code: number of failed tests (0 = all passed).

param(
    [string]$MountPoint = "$env:USERPROFILE\CipherBox",
    [string]$ApiUrl = "http://localhost:3000"
)

$TestSecret = if ($env:TEST_SECRET) { $env:TEST_SECRET } else { "e2e-test-secret-ci-only" }

$ErrorActionPreference = "Continue"

$TestEmail = "dev-key@cipherbox.local"
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$TestFile = "sync-test-$(Get-Random).txt"
$OriginalContent = "Original content from FUSE mount"
$EditedContent = "Edited content from SDK client"

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

function Ensure-SdkRuntime {
    $paths = @(
        "packages/sdk-core/dist/index.mjs",
        "packages/api-client/dist/index.mjs",
        "packages/core/dist/index.mjs",
        "packages/crypto/dist/index.mjs"
    )

    $allExist = $true
    foreach ($p in $paths) {
        if (-not (Test-Path (Join-Path $RepoRoot $p))) {
            $allExist = $false
            break
        }
    }

    if ($allExist) { return }

    Write-Host "Building SDK dependencies..."
    & pnpm --dir $RepoRoot --filter @cipherbox/crypto build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/crypto" }
    & pnpm --dir $RepoRoot --filter @cipherbox/core build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/core" }
    & pnpm --dir $RepoRoot --filter @cipherbox/api-client build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/api-client" }
    & pnpm --dir $RepoRoot --filter @cipherbox/sdk-core build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/sdk-core" }
}

function Invoke-SdkVerify {
    param([string]$ExpectedContent)
    $verifierPath = Join-Path $RepoRoot "packages/sdk-core/scripts/verify-filepointer.mts"
    $env:TEST_SECRET = $TestSecret
    $output = & pnpm exec tsx $verifierPath `
        --api-url $ApiUrl `
        --email $TestEmail `
        --file-name $TestFile `
        --expected-content $ExpectedContent 2>&1 | Out-String
    return @($LASTEXITCODE, $output.Trim())
}

function Invoke-SdkEdit {
    param([string]$NewContent)
    $editorPath = Join-Path $RepoRoot "packages/sdk-core/scripts/edit-filepointer.mts"
    $env:TEST_SECRET = $TestSecret
    $output = & pnpm exec tsx $editorPath `
        --api-url $ApiUrl `
        --email $TestEmail `
        --file-name $TestFile `
        --new-content $NewContent 2>&1 | Out-String
    return @($LASTEXITCODE, $output.Trim())
}

Write-Host "=== Cross-Client Sync Tests ==="
Write-Host "Mount point: $MountPoint"
Write-Host "API URL:     $ApiUrl"
Write-Host "Test email:  $TestEmail"
Write-Host "Test file:   $TestFile"
Write-Host ""

try {
    Ensure-SdkRuntime
} catch {
    Write-Host "FATAL: Failed to build SDK dependencies ($_)"
    exit 1
}

# ---- Test 1: Write file via FUSE mount ----
Write-Host "--- Test 1: Write file via FUSE mount ---"
try {
    Set-Content -Path "$MountPoint\$TestFile" -Value $OriginalContent -NoNewline -ErrorAction Stop
    Start-Sleep -Seconds 2
    # Trigger readdir to drain upload completions
    Get-ChildItem -Path $MountPoint -ErrorAction SilentlyContinue | Out-Null
} catch {
    Test-Fail "Write file via FUSE mount ($_)"
    Write-Host "FATAL: Cannot proceed without FUSE write."
    Write-Host ""
    Write-Host "=== Cross-Client Sync Results ==="
    Write-Host "  Passed: $Pass"
    Write-Host "  Failed: $Fail"
    Write-Host "=================================="
    exit $Fail
}

$FuseContent = $null
try { $FuseContent = (Get-Content -Path "$MountPoint\$TestFile" -Raw -ErrorAction Stop) } catch {}
if ($FuseContent -eq $OriginalContent) {
    Test-Pass "Write file via FUSE mount"
} else {
    Test-Fail "Write file via FUSE mount (got: '$FuseContent')"
}

# ---- Test 2: Wait for file to be visible via SDK ----
Write-Host "--- Test 2: Wait for file to be visible via SDK ---"
$SdkVerifyOk = $false
$VerifyOutput = ""
for ($attempt = 1; $attempt -le 24 -and -not $SdkVerifyOk; $attempt++) {
    # Trigger readdir each iteration to drain upload completions
    try { Get-Item "$MountPoint\$TestFile" -ErrorAction SilentlyContinue | Out-Null } catch {}
    Get-ChildItem -Path $MountPoint -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 5
    $result = Invoke-SdkVerify -ExpectedContent $OriginalContent
    $exitCode = [int]$result[0]
    $VerifyOutput = [string]$result[1]
    if ($exitCode -eq 0) {
        $SdkVerifyOk = $true
    } else {
        Write-Host "  SDK verify attempt ${attempt}: $VerifyOutput"
    }
}

if ($SdkVerifyOk) {
    Test-Pass "File visible and decryptable via SDK"
    Write-Host "  $VerifyOutput"
} else {
    Test-Fail "File not visible via SDK after 120s"
    Write-Host "FATAL: Cannot proceed without SDK-visible file."
    Write-Host ""
    Write-Host "=== Cross-Client Sync Results ==="
    Write-Host "  Passed: $Pass"
    Write-Host "  Failed: $Fail"
    Write-Host "=================================="
    try { Remove-Item -Path "$MountPoint\$TestFile" -Force -ErrorAction SilentlyContinue } catch {}
    exit $Fail
}

# ---- Test 3: Edit file via SDK ----
Write-Host "--- Test 3: Edit file via SDK ---"
$editResult = Invoke-SdkEdit -NewContent $EditedContent
$editExit = [int]$editResult[0]
$editOutput = [string]$editResult[1]
if ($editExit -eq 0) {
    Test-Pass "Edit file via SDK"
    Write-Host "  $editOutput"
} else {
    Test-Fail "Edit file via SDK ($editOutput)"
    Write-Host "FATAL: Cannot test sync without successful edit."
    Write-Host ""
    Write-Host "=== Cross-Client Sync Results ==="
    Write-Host "  Passed: $Pass"
    Write-Host "  Failed: $Fail"
    Write-Host "=================================="
    try { Remove-Item -Path "$MountPoint\$TestFile" -Force -ErrorAction SilentlyContinue } catch {}
    exit $Fail
}

# ---- Test 4: Verify edit persisted via SDK ----
Write-Host "--- Test 4: Verify edit persisted via SDK ---"
Start-Sleep -Seconds 2
$verifyEditResult = Invoke-SdkVerify -ExpectedContent $EditedContent
$verifyEditExit = [int]$verifyEditResult[0]
$verifyEditOutput = [string]$verifyEditResult[1]
if ($verifyEditExit -eq 0) {
    Test-Pass "Edited content verified via SDK"
    Write-Host "  $verifyEditOutput"
} else {
    Test-Fail "Edited content not verified via SDK ($verifyEditOutput)"
}

# ---- Test 5: Wait for FUSE mount to pick up edited content ----
Write-Host "--- Test 5: Wait for FUSE mount to detect edit ---"
# The FUSE mount polls folder metadata every 30s. After detecting a newer
# modified_at on the FilePointer, it re-resolves the file's IPNS record
# to pick up the new CID. Allow up to 120s for two full polling cycles.
# IMPORTANT: Get-ChildItem triggers readdir which is a reliable operation
# for calling drain_refresh_completions() -> populate_folder().
$SyncOk = $false
for ($attempt = 1; $attempt -le 24 -and -not $SyncOk; $attempt++) {
    Start-Sleep -Seconds 5
    # Trigger readdir to drain refresh completions and detect modified_at changes
    Get-ChildItem -Path $MountPoint -ErrorAction SilentlyContinue | Out-Null
    $FuseContent = $null
    try { $FuseContent = (Get-Content -Path "$MountPoint\$TestFile" -Raw -ErrorAction Stop) } catch {}
    if ($FuseContent -eq $EditedContent) {
        $SyncOk = $true
        Write-Host "  Sync detected on attempt $attempt ($($attempt * 5)s)"
    } else {
        Write-Host "  Sync poll attempt ${attempt}: content still original"
    }
}

if ($SyncOk) {
    Test-Pass "FUSE mount picked up edited content"
} else {
    Test-Fail "FUSE mount still shows original content after 120s (got: '$FuseContent')"
}

# ---- Cleanup ----
Write-Host "--- Cleanup ---"
try { Remove-Item -Path "$MountPoint\$TestFile" -Force -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Seconds 2

# ---- Summary ----
Write-Host ""
Write-Host "=== Cross-Client Sync Results ==="
Write-Host "  Passed: $Pass"
Write-Host "  Failed: $Fail"
Write-Host "=================================="

exit $Fail
