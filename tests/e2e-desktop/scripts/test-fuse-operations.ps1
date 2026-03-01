# test-fuse-operations.ps1 -- Exercise FUSE mount file I/O operations (Windows).
#
# Usage: .\test-fuse-operations.ps1 [-MountPoint <path>]
#   -MountPoint  Path to FUSE mount (default: $env:USERPROFILE\CipherBox)
#
# Tests: create, read, overwrite, mkdir, nested write, binary round-trip,
#        rename, delete file, delete directory.
#
# Exit code: number of failed tests (0 = all passed).

param(
    [string]$MountPoint = "$env:USERPROFILE\CipherBox"
)

$ErrorActionPreference = "Continue"

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

Write-Host "=== FUSE File I/O Tests ==="
Write-Host "Mount point: $MountPoint"
Write-Host ""

# ---- Test 1: Create and read text file ----
Write-Host "--- Test 1: Create and read text file ---"
Set-Content -Path "$MountPoint\e2e-test.txt" -Value "Hello from CI" -NoNewline
Start-Sleep -Seconds 3
$Content = Get-Content -Path "$MountPoint\e2e-test.txt" -Raw
if ($Content.Trim() -eq "Hello from CI") {
    Test-Pass "Create and read text file"
} else {
    Test-Fail "Create and read text file (got: '$Content')"
}

# ---- Test 2: Create directory ----
Write-Host "--- Test 2: Create directory ---"
New-Item -ItemType Directory -Path "$MountPoint\e2e-folder" -Force | Out-Null
if (Test-Path "$MountPoint\e2e-folder" -PathType Container) {
    Test-Pass "Create directory"
} else {
    Test-Fail "Create directory"
}

# ---- Test 3: Write file in subdirectory ----
Write-Host "--- Test 3: Write file in subdirectory ---"
Set-Content -Path "$MountPoint\e2e-folder\nested.txt" -Value "Nested content" -NoNewline
Start-Sleep -Seconds 3
$Nested = Get-Content -Path "$MountPoint\e2e-folder\nested.txt" -Raw
if ($Nested.Trim() -eq "Nested content") {
    Test-Pass "Write file in subdirectory"
} else {
    Test-Fail "Write file in subdirectory (got: '$Nested')"
}

# ---- Test 4: Overwrite file (modify) ----
Write-Host "--- Test 4: Overwrite file ---"
Set-Content -Path "$MountPoint\e2e-test.txt" -Value "Modified content" -NoNewline
Start-Sleep -Seconds 3
$Modified = Get-Content -Path "$MountPoint\e2e-test.txt" -Raw
if ($Modified.Trim() -eq "Modified content") {
    Test-Pass "Overwrite file"
} else {
    Test-Fail "Overwrite file (got: '$Modified')"
}

# ---- Test 5: Binary file round-trip ----
Write-Host "--- Test 5: Binary file round-trip ---"
try {
    $TempBinary = "$env:TEMP\e2e-binary.bin"
    $MountBinary = "$MountPoint\e2e-binary.bin"
    $Bytes = New-Object byte[] (256 * 1024)
    $Rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
    $Rng.GetBytes($Bytes)
    $Rng.Dispose()
    [System.IO.File]::WriteAllBytes($TempBinary, $Bytes)
    Copy-Item -Path $TempBinary -Destination $MountBinary -ErrorAction Stop
    Start-Sleep -Seconds 5
    $HashOrig = (Get-FileHash -Path $TempBinary -Algorithm SHA256).Hash
    $HashMount = (Get-FileHash -Path $MountBinary -Algorithm SHA256).Hash
    if ($HashOrig -eq $HashMount) {
        Test-Pass "Binary file round-trip (256KB)"
    } else {
        Test-Fail "Binary file round-trip (orig: $HashOrig, mount: $HashMount)"
    }
} catch {
    Test-Fail "Binary file round-trip (exception: $($_.Exception.Message))"
}

# ---- Test 6: Rename file ----
Write-Host "--- Test 6: Rename file ---"
try {
    Move-Item -Path "$MountPoint\e2e-test.txt" -Destination "$MountPoint\e2e-renamed.txt" -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    $OldExists = Test-Path "$MountPoint\e2e-test.txt"
    $NewExists = Test-Path "$MountPoint\e2e-renamed.txt"
    if (-not $OldExists -and $NewExists) {
        $Renamed = Get-Content -Path "$MountPoint\e2e-renamed.txt" -Raw
        if ($Renamed.Trim() -eq "Modified content") {
            Test-Pass "Rename file"
        } else {
            Test-Fail "Rename file (content changed: '$Renamed')"
        }
    } else {
        Test-Fail "Rename file (old exists: $OldExists, new exists: $NewExists)"
    }
} catch {
    Test-Fail "Rename file (exception: $($_.Exception.Message))"
}

# ---- Test 7: Delete file ----
Write-Host "--- Test 7: Delete file ---"
try {
    Remove-Item -Path "$MountPoint\e2e-renamed.txt" -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    if (-not (Test-Path "$MountPoint\e2e-renamed.txt")) {
        Test-Pass "Delete file"
    } else {
        Test-Fail "Delete file (still exists)"
    }
} catch {
    Test-Fail "Delete file (exception: $($_.Exception.Message))"
}

# ---- Test 8: Delete directory ----
Write-Host "--- Test 8: Delete directory ---"
try {
    # Delete contents first, then the directory itself (more reliable on FUSE)
    Get-ChildItem -Path "$MountPoint\e2e-folder" -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction Stop
    Start-Sleep -Seconds 1
    Remove-Item -Path "$MountPoint\e2e-folder" -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    if (-not (Test-Path "$MountPoint\e2e-folder")) {
        Test-Pass "Delete directory"
    } else {
        Test-Fail "Delete directory (still exists)"
    }
} catch {
    Test-Fail "Delete directory (exception: $($_.Exception.Message))"
}

# ---- Test 9: Cleanup ----
Write-Host "--- Test 9: Cleanup ---"
Remove-Item -Path $MountBinary -Force -ErrorAction SilentlyContinue
Remove-Item -Path $TempBinary -Force -ErrorAction SilentlyContinue
if ((-not (Test-Path $MountBinary)) -and (-not (Test-Path $TempBinary))) {
    Test-Pass "Cleanup"
} else {
    Test-Fail "Cleanup (artifacts still exist)"
}

# ---- Summary ----
Write-Host ""
Write-Host "=== FUSE File I/O Results ==="
Write-Host "  Passed: $Pass"
Write-Host "  Failed: $Fail"
Write-Host "=============================="

exit $Fail
