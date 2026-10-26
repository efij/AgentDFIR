#Requires -Version 5.1
<#
AgentDFIR installer for Windows (PowerShell 5.1 or 7, x64 or ARM64).

  Command Prompt or PowerShell (the same line works in both, and on machines
  that run PowerShell in Constrained Language Mode):
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-Item Env:AGENTDFIR_RUN 1; irm https://raw.githubusercontent.com/efij/AgentDFIR/main/install.ps1 | iex"
  PowerShell only:
    $env:AGENTDFIR_RUN=1; irm https://raw.githubusercontent.com/efij/AgentDFIR/main/install.ps1 | iex

The script uses only cmdlets and environment variables, no .NET method calls,
so it also runs where AppLocker / WDAC puts PowerShell in Constrained Language
Mode. The latest version is resolved from the github.com release redirect when
the GitHub API is unreachable or rate-limited.

What it does, in order:
  1. detects the CPU (x64 / ARM64), 2. downloads the raw release .exe and SHA256SUMS.txt,
  3. verifies the checksum, 4. installs agentdfir.exe to $env:AGENTDFIR_INSTALL_DIR
     (default %LOCALAPPDATA%\agentdfir\bin) and adds that folder to your user PATH
     and to this session's PATH, so `agentdfir run` works right away.
The installed file carries no mark-of-the-web, so SmartScreen does not prompt.

Environment:
  AGENTDFIR_VERSION      tag to install (default: latest release), e.g. v0.16.0
  AGENTDFIR_INSTALL_DIR  target directory (default: %LOCALAPPDATA%\agentdfir\bin)
  AGENTDFIR_BASE_URL     asset base URL override (tests use file:///…/dist)
  AGENTDFIR_RUN          1 = start `agentdfir run` when the install finishes (cleared afterwards)

macOS / Linux: curl -fsSL https://raw.githubusercontent.com/efij/AgentDFIR/main/install.sh | sh
#>
& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $repo = 'efij/AgentDFIR'
  $installDir = if ($env:AGENTDFIR_INSTALL_DIR) { $env:AGENTDFIR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'agentdfir\bin' }
  $version = $env:AGENTDFIR_VERSION

  # PowerShell 5.1 defaults to TLS 1.0; GitHub needs 1.2. Not allowed in
  # Constrained Language Mode, where the OS default (1.2 on supported
  # Windows) applies, so a failure here is ignored.
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

  $ua = @{ 'User-Agent' = 'agentdfir-install' }
  function Fetch($url, $out) {
    if ($url -like 'file:*') {
      $local = ($url -replace '^file:/*', '') -replace '/', '\'
      if ($local -notmatch '^[A-Za-z]:') { $local = '\\' + $local }
      Copy-Item -LiteralPath $local -Destination $out -Force
      return
    }
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -Headers $ua
  }

  $osArch = $null
  try { $osArch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch {}
  if (-not $osArch) { $osArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE } }
  switch -Regex ($osArch) {
    '^(X64|AMD64)$' { $arch = 'amd64' }
    '^ARM64$'       { $arch = 'arm64' }
    default         { throw "install.ps1: unsupported architecture '$osArch' (x64 and ARM64 are supported)" }
  }

  if (-not $version) {
    try {
      $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing -Headers $ua
      $version = $rel.tag_name
    } catch {}
    if (-not $version) {
      # The API is rate-limited per IP (shared office networks run out) or
      # blocked: follow github.com's /releases/latest redirect instead.
      try {
        $page = Invoke-WebRequest -Uri "https://github.com/$repo/releases/latest" -UseBasicParsing -Headers $ua
        $final = $null
        try { $final = $page.BaseResponse.ResponseUri.AbsoluteUri } catch {}
        if (-not $final) { try { $final = $page.BaseResponse.RequestMessage.RequestUri.AbsoluteUri } catch {} }
        if ("$final" -match '/releases/tag/(v[0-9][^/?#]*)') { $version = $Matches[1] }
        elseif ($page.Content -match '/releases/tag/(v[0-9][^/"?#]*)') { $version = $Matches[1] }
      } catch {}
    }
    if (-not $version) { throw 'install.ps1: could not resolve the latest release; set AGENTDFIR_VERSION (e.g. v4.0.0) and run again' }
  }
  $base = if ($env:AGENTDFIR_BASE_URL) { $env:AGENTDFIR_BASE_URL } else { "https://github.com/$repo/releases/download/$version" }
  $asset = "agentdfir-$version-windows-$arch.exe"

  $tmp = Join-Path $env:TEMP ('agentdfir-' + (Get-Random) + '-' + (Get-Random))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "agentdfir $version (windows/$arch)"
    Write-Host "downloading $asset"
    Fetch "$base/$asset" (Join-Path $tmp $asset)
    Fetch "$base/SHA256SUMS.txt" (Join-Path $tmp 'SHA256SUMS.txt')

    $expected = $null
    foreach ($l in (Get-Content -LiteralPath (Join-Path $tmp 'SHA256SUMS.txt'))) {
      $parts = -split $l
      if ($parts.Count -ge 2 -and ($parts[1] -replace '^\*', '') -eq $asset) { $expected = "$($parts[0])".ToLower(); break }
    }
    if (-not $expected) { throw "install.ps1: $asset not listed in SHA256SUMS.txt" }
    $actual = "$((Get-FileHash -LiteralPath (Join-Path $tmp $asset) -Algorithm SHA256).Hash)".ToLower()
    if ($expected -ne $actual) { throw "install.ps1: checksum mismatch for $asset`n  expected $expected`n  actual   $actual" }
    Write-Host "checksum ok  $actual"

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $dest = Join-Path $installDir 'agentdfir.exe'
    Unblock-File -Path (Join-Path $tmp $asset) -ErrorAction SilentlyContinue
    Move-Item -LiteralPath (Join-Path $tmp $asset) -Destination $dest -Force
  } finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
  }

  Write-Host "installed $dest"
  & $dest version
  if ($LASTEXITCODE -ne 0) { throw "install.ps1: '$dest version' exited $LASTEXITCODE" }

  # PATH: this session now, and the user's PATH for every new terminal.
  $sep = ';'
  if (($env:Path -split $sep) -notcontains $installDir) { $env:Path = "$installDir$sep$env:Path" }
  # The user PATH lives in HKCU\Environment; the registry provider works in
  # Constrained Language Mode, [Environment]::SetEnvironmentVariable does not
  # (but also tells running programs, so it is tried first).
  $userPath = $null
  try { $userPath = (Get-ItemProperty -Path 'HKCU:\Environment' -Name Path -ErrorAction Stop).Path } catch {}
  if (($userPath -split $sep) -notcontains $installDir) {
    $new = if ($userPath) { "$userPath$sep$installDir" } else { $installDir }
    $done = $false
    try { [Environment]::SetEnvironmentVariable('Path', $new, 'User'); $done = $true } catch {}
    if (-not $done) {
      try { Set-ItemProperty -Path 'HKCU:\Environment' -Name Path -Value $new -Type ExpandString -ErrorAction Stop; $done = $true } catch {}
    }
    if ($done) { Write-Host "added $installDir to your PATH (new terminals pick it up)" }
    else { Write-Host "could not add $installDir to your user PATH; run it as $dest" }
  }

  # Start the run here rather than relying on a command typed after `| iex`:
  # that tail is lost whenever the one-liner is split, wrapped or pasted as
  # the script body, and the install then looks like it did nothing.
  $runNow = $env:AGENTDFIR_RUN -eq '1'
  Remove-Item Env:\AGENTDFIR_RUN -ErrorAction SilentlyContinue
  Write-Host ""
  if ($runNow) {
    Write-Host "starting: agentdfir run"
    & $dest run
  } else {
    Write-Host "Next: agentdfir run    (finds every AI agent on this machine, collects, analyzes and opens the results)"
  }
}
