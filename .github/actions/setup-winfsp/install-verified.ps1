# Download a file, check its SHA-256, and only then run $Install on it.
# A download was once cut mid-stream, so a download error retries; a hash
# mismatch never does. Windows PowerShell 5.1 has no -MaximumRetryCount.
param(
  [Parameter(Mandatory = $true)][string]$Uri,
  [Parameter(Mandatory = $true)][string]$OutFile,
  [Parameter(Mandatory = $true)][string]$Sha256,
  [Parameter(Mandatory = $true)][scriptblock]$Install,
  [int]$Attempts = 3,
  [int]$BackoffSec = 10,
  # Bounds the connection and the response headers. A stalled body falls to
  # the .NET read timeout of 300 s.
  [int]$TimeoutSec = 120
)
$ErrorActionPreference = 'Stop'

for ($i = 1; ; $i++) {
  try {
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec $TimeoutSec
    break
  } catch {
    if ($i -ge $Attempts) { throw }
    Write-Warning "Download attempt $i of $Attempts failed: $($_.Exception.Message)"
    Start-Sleep -Seconds ($BackoffSec * $i)
  }
}

$actual = (Get-FileHash $OutFile -Algorithm SHA256).Hash
if ($actual -ne $Sha256) {
  throw "Hash mismatch for ${Uri}: expected $Sha256, got $actual"
}
& $Install $OutFile
