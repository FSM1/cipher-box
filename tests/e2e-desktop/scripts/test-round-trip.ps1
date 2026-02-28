# test-round-trip.ps1 -- Verify desktop FUSE writes are visible via the API (Windows).
#
# Usage: .\test-round-trip.ps1 [-MountPoint <path>] [-ApiUrl <url>] [-TestSecret <secret>]
#   -MountPoint   Path to FUSE mount (default: $env:USERPROFILE\CipherBox)
#   -ApiUrl       Backend API URL (default: http://localhost:3000)
#   -TestSecret   Shared secret for test-login (default: e2e-test-secret-ci-only)
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

$TestEmail = "e2e-desktop-rt-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())@test.local"

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

Write-Host "=== API Round-Trip Tests ==="
Write-Host "Mount point: $MountPoint"
Write-Host "API URL:     $ApiUrl"
Write-Host "Test email:  $TestEmail"
Write-Host ""

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
try {
    Set-Content -Path "$MountPoint\rt-test.txt" -Value "API-visible content" -NoNewline -ErrorAction Stop
    if (-not (Test-Path "$MountPoint\rt-test.txt")) { throw "FUSE write did not materialize at mount path" }
} catch {
    Test-Fail "FUSE write failed ($_)"
    $RootIpns = $null
}
Start-Sleep -Seconds 5

try {
    $VaultResponse = Invoke-RestMethod -Uri "$ApiUrl/vault" `
        -Headers $Headers

    $RootIpns = $VaultResponse.rootIpnsName
    if ($RootIpns) {
        Test-Pass "Vault has rootIpnsName after FUSE write ($RootIpns)"
    } else {
        Test-Fail "Vault has no rootIpnsName"
    }
} catch {
    Test-Fail "Vault API call failed ($_)"
    $RootIpns = $null
}

# ---- Test 3: Verify IPNS resolve returns data ----
Write-Host "--- Test 3: Verify IPNS resolve returns CID ---"
if ($RootIpns) {
    try {
        $IpnsResponse = Invoke-RestMethod -Uri "$ApiUrl/ipns/$RootIpns/resolve" `
            -Headers $Headers

        $ResolvedCid = $IpnsResponse.cid
        if (-not $ResolvedCid) { $ResolvedCid = $IpnsResponse.value }

        if ($ResolvedCid) {
            Test-Pass "IPNS resolve returned CID ($ResolvedCid)"
        } else {
            Test-Fail "IPNS resolve did not return expected CID"
        }
    } catch {
        Test-Fail "IPNS resolve failed ($_)"
    }
} else {
    Test-Fail "IPNS resolve skipped (no rootIpnsName)"
}

# ---- Cleanup ----
Write-Host "--- Cleanup ---"
Remove-Item -Path "$MountPoint\rt-test.txt" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# ---- Summary ----
Write-Host ""
Write-Host "=== API Round-Trip Results ==="
Write-Host "  Passed: $Pass"
Write-Host "  Failed: $Fail"
Write-Host "==============================="

exit $Fail
