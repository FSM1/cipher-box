# install-verified.ps1 against a local listener that cuts the first $Cut
# responses halfway through the body, as the release host once did.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$helper = Join-Path $PSScriptRoot 'install-verified.ps1'
$payload = [byte[]]((1..255) * 256)
$sha = [BitConverter]::ToString(
  [Security.Cryptography.SHA256]::Create().ComputeHash($payload)).Replace('-', '')

function Invoke-Case([string]$Name, [int]$Cut, [string]$Sha256, [bool]$ExpectInstall, [int]$ExpectRequests) {
  $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
  $probe.Start(); $port = $probe.LocalEndpoint.Port; $probe.Stop()
  $listener = New-Object Net.HttpListener
  $listener.Prefixes.Add("http://127.0.0.1:$port/")
  $listener.Start()
  $state = [hashtable]::Synchronized(@{ requests = 0 })
  $server = [powershell]::Create().AddScript({
      param($listener, $state, $payload, $cut)
      while ($listener.IsListening) {
        try { $ctx = $listener.GetContext() } catch { return }
        $state.requests++
        $res = $ctx.Response
        $res.ContentLength64 = $payload.Length
        if ($state.requests -le $cut) {
          $res.OutputStream.Write($payload, 0, [int]($payload.Length / 2))
          $res.OutputStream.Flush()
          $res.Abort()
        } else {
          $res.OutputStream.Write($payload, 0, $payload.Length)
          $res.Close()
        }
      }
    }).AddArgument($listener).AddArgument($state).AddArgument($payload).AddArgument($Cut)
  $handle = $server.BeginInvoke()

  $installs = @{ n = 0 }
  $out = Join-Path ([IO.Path]::GetTempPath()) "install-verified-$([guid]::NewGuid()).bin"
  $threw = $false
  try {
    & $helper -Uri "http://127.0.0.1:$port/file.msi" -OutFile $out -Sha256 $Sha256 `
      -BackoffSec 0 -TimeoutSec 10 -Install { $installs.n++ }
  } catch {
    $threw = $true
    Write-Host "  $Name threw: $($_.Exception.Message)"
  } finally {
    $listener.Stop(); $listener.Close()
    [void]$server.EndInvoke($handle); $server.Dispose()
    Remove-Item $out -ErrorAction SilentlyContinue
  }

  $wrong = @()
  if ($threw -eq $ExpectInstall) { $wrong += "threw=$threw" }
  if ($installs.n -ne [int]$ExpectInstall) { $wrong += "installs=$($installs.n)" }
  if ($state.requests -ne $ExpectRequests) { $wrong += "requests=$($state.requests), want $ExpectRequests" }
  if ($wrong.Count -gt 0) { return "${Name}: $($wrong -join '; ')" }
  Write-Host "ok: $Name"
}

$failures = @(
  Invoke-Case 'a cut first download passes on try 2' 1 $sha $true 2
  Invoke-Case 'three cut downloads fail with no install' 99 $sha $false 3
  Invoke-Case 'a wrong hash fails with no install and no retry' 0 ('0' * 64) $false 1
) | Where-Object { $_ }
if ($failures) { throw "install-verified.ps1:`n$($failures -join "`n")" }
