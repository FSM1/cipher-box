# test-round-trip.ps1 -- Verify desktop FUSE writes are visible via the API (Windows).
#
# Usage: .\test-round-trip.ps1 [-MountPoint <path>] [-ApiUrl <url>]
#   -MountPoint   Path to FUSE mount (default: $env:USERPROFILE\CipherBox)
#   -ApiUrl       Backend API URL (default: http://localhost:3000)
#
# Environment:
#   TEST_SECRET   Shared secret for test-login (default: e2e-test-secret-ci-only)
#
# The server is zero-knowledge -- it cannot decrypt file contents.
# These tests prove the pipeline: FUSE write -> encrypt -> IPFS upload -> IPNS publish -> API visibility.
#
# Exit code: number of failed tests (0 = all passed).

param(
    [string]$MountPoint = "$env:USERPROFILE\CipherBox",
    [string]$ApiUrl = "http://localhost:3000"
)

$TestSecret = if ($env:TEST_SECRET) { $env:TEST_SECRET } else { "e2e-test-secret-ci-only" }

$ErrorActionPreference = "Continue"

# Use the same email as the dev-key auth flow so we query the same user's vault
$TestEmail = "dev-key@cipherbox.local"
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$TestFile = "rt-test-$PID-$(Get-Random).txt"
$TestContent = "API-visible content"

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

function Ensure-VerifierRuntime {
    $sdkCoreDist = Join-Path $RepoRoot "packages/sdk-core/dist/index.mjs"
    $apiClientDist = Join-Path $RepoRoot "packages/api-client/dist/index.mjs"

    if ((Test-Path $sdkCoreDist) -and (Test-Path $apiClientDist)) {
        return
    }

    & pnpm --dir $RepoRoot --filter @cipherbox/crypto build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/crypto" }

    & pnpm --dir $RepoRoot --filter @cipherbox/core build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/core" }

    & pnpm --dir $RepoRoot --filter @cipherbox/api-client build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/api-client" }

    & pnpm --dir $RepoRoot --filter @cipherbox/sdk-core build
    if ($LASTEXITCODE -ne 0) { throw "Failed to build @cipherbox/sdk-core" }
}

Write-Host "=== API Round-Trip Tests ==="
Write-Host "Mount point: $MountPoint"
Write-Host "API URL:     $ApiUrl"
Write-Host "Test email:  $TestEmail"
Write-Host "Test file:   $TestFile"
Write-Host ""

Ensure-VerifierRuntime

function Invoke-FilePointerVerifier {
    $verifierPath = Join-Path $RepoRoot "packages/sdk-core/scripts/verify-filepointer.mjs"
    $env:TEST_SECRET = $TestSecret
    $output = & node $verifierPath `
        --api-url $ApiUrl `
        --email $TestEmail `
        --file-name $TestFile `
        --expected-content $TestContent 2>&1 | Out-String

    return @($LASTEXITCODE, $output.Trim())
}

# ---- Test 1: Authenticate via test-login ----
Write-Host "--- Test 1: Authenticate via test-login ---"
$Body = @{
    email  = $TestEmail
    secret = $TestSecret
} | ConvertTo-Json

try {
    $AuthResponse = Invoke-RestMethod -Uri "$ApiUrl/auth/test-login" `
        -Method Post `
        -ContentType "application/json" `
        -Body $Body

    $AccessToken = $AuthResponse.accessToken
    if ($AccessToken) {
        Test-Pass "Authenticate via test-login"
    } else {
        Test-Fail "Authenticate via test-login (no accessToken in response)"
        Write-Host "FATAL: Cannot proceed without authentication."
        Write-Host ""
        Write-Host "=== API Round-Trip Results ==="
        Write-Host "  Passed: $Pass"
        Write-Host "  Failed: $Fail"
        Write-Host "==============================="
        exit $Fail
    }
} catch {
    Test-Fail "Authenticate via test-login ($_)"
    Write-Host "FATAL: Cannot proceed without authentication."
    Write-Host ""
    Write-Host "=== API Round-Trip Results ==="
    Write-Host "  Passed: $Pass"
    Write-Host "  Failed: $Fail"
    Write-Host "==============================="
    exit $Fail
}

$Headers = @{ Authorization = "Bearer $AccessToken" }

# ---- Test 2: Desktop writes file, API verifies vault exists ----
Write-Host "--- Test 2: Verify vault has content after FUSE write ---"
$FuseWriteSucceeded = $false
try {
    Set-Content -Path "$MountPoint\$TestFile" -Value $TestContent -NoNewline -ErrorAction Stop
    if (-not (Test-Path "$MountPoint\$TestFile")) { throw "FUSE write did not materialize at mount path" }
    $FuseWriteSucceeded = $true
} catch {
    Test-Fail "FUSE write failed ($_)"
}
if ($FuseWriteSucceeded) {
    $RootIpns = $null
    for ($attempt = 1; $attempt -le 12 -and -not $RootIpns; $attempt++) {
        Start-Sleep -Seconds 5
        try {
            $VaultResponse = Invoke-RestMethod -Uri "$ApiUrl/vault" -Headers $Headers
            $RootIpns = $VaultResponse.rootIpnsName
        } catch {
            Write-Host "  Vault poll attempt $attempt failed: $_"
        }
    }
    if ($RootIpns) {
        Test-Pass "Vault has rootIpnsName after FUSE write ($RootIpns)"
    } else {
        Test-Fail "Vault has no rootIpnsName after 60s polling"
    }
} else {
    Test-Fail "Vault verification skipped (FUSE write failed)"
    $RootIpns = $null
}

# ---- Test 3: Verify FilePointer and per-file IPNS metadata resolve ----
Write-Host "--- Test 3: Verify FilePointer and per-file IPNS metadata ---"
$VerifySucceeded = $false
$VerifyOutput = ""
for ($attempt = 1; $attempt -le 12 -and -not $VerifySucceeded; $attempt++) {
    Start-Sleep -Seconds 5
    $verifyResult = Invoke-FilePointerVerifier
    $verifyExit = [int]$verifyResult[0]
    $VerifyOutput = [string]$verifyResult[1]
    if ($verifyExit -eq 0) {
        $VerifySucceeded = $true
    } else {
        Write-Host "  FilePointer verify attempt $attempt failed: $VerifyOutput"
    }
}

if ($VerifySucceeded) {
    Test-Pass "FilePointer exists and per-file IPNS metadata resolves"
    Write-Host "  $VerifyOutput"
} else {
    Test-Fail "FilePointer/per-file IPNS verification failed after 60s"
}

# ---- Test 4: Verify fresh client reload can still resolve file metadata ----
Write-Host "--- Test 4: Verify fresh client reload resolves file metadata ---"
Start-Sleep -Seconds 2
$reloadResult = Invoke-FilePointerVerifier
$reloadExit = [int]$reloadResult[0]
$reloadOutput = [string]$reloadResult[1]
if ($reloadExit -eq 0) {
    Test-Pass "Fresh client reload resolves file metadata and content"
    Write-Host "  $reloadOutput"
} else {
    Test-Fail "Fresh client reload failed to resolve file metadata ($reloadOutput)"
}

# ---- Test 5: Verify IPNS resolve returns data ----
Write-Host "--- Test 5: Verify IPNS resolve returns CID ---"
if ($RootIpns) {
    $ResolvedCid = $null
    for ($attempt = 1; $attempt -le 12 -and -not $ResolvedCid; $attempt++) {
        Start-Sleep -Seconds 2
        try {
            $IpnsResponse = Invoke-RestMethod -Uri "$ApiUrl/ipns/resolve?ipnsName=$RootIpns" -Headers $Headers
            $ResolvedCid = if ($IpnsResponse.cid) { $IpnsResponse.cid } else { $IpnsResponse.value }
        } catch {
            Write-Host "  IPNS resolve attempt $attempt failed: $_"
        }
    }
    if ($ResolvedCid) {
        Test-Pass "IPNS resolve returned CID ($ResolvedCid)"
    } else {
        Test-Fail "IPNS resolve did not return expected CID after 24s polling"
    }
} else {
    Test-Fail "IPNS resolve skipped (no rootIpnsName)"
}

# ---- Cleanup ----
Write-Host "--- Cleanup ---"
Remove-Item -Path "$MountPoint\$TestFile" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# ---- Summary ----
Write-Host ""
Write-Host "=== API Round-Trip Results ==="
Write-Host "  Passed: $Pass"
Write-Host "  Failed: $Fail"
Write-Host "==============================="

exit $Fail
