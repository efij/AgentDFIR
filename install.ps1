#Requires -Version 5.1
<#
AgentDFIR installer for Windows (PowerShell 5.1 or 7, x64 or ARM64).

  irm https://raw.githubusercontent.com/efij/AgentDFIR/main/install.ps1 | iex

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

macOS / Linux: curl -fsSL https://raw.githubusercontent.com/efij/AgentDFIR/main/install.sh | sh
#>
& {
  $ErrorActionPreference = 'Stop'
  $ProgressPreference = 'SilentlyContinue'
  $repo = 'efij/AgentDFIR'
  $installDir = if ($env:AGENTDFIR_INSTALL_DIR) { $env:AGENTDFIR_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'agentdfir\bin' }
  $version = $env:AGENTDFIR_VERSION

  # PowerShell 5.1 defaults to TLS 1.0; GitHub needs 1.2.
  try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

  function Fetch($url, $out) {
    if ($url -like 'file:*') { Copy-Item -LiteralPath ([Uri]$url).LocalPath -Destination $out -Force; return }
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -Headers @{ 'User-Agent' = 'agentdfir-install' }
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
    $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing -Headers @{ 'User-Agent' = 'agentdfir-install' }
    $version = $rel.tag_name
    if (-not $version) { throw 'install.ps1: could not resolve the latest release; set AGENTDFIR_VERSION' }
  }
  $base = if ($env:AGENTDFIR_BASE_URL) { $env:AGENTDFIR_BASE_URL } else { "https://github.com/$repo/releases/download/$version" }
  $asset = "agentdfir-$version-windows-$arch.exe"

  $tmp = Join-Path ([IO.Path]::GetTempPath()) ('agentdfir-' + [Guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Write-Host "agentdfir $version (windows/$arch)"
    Write-Host "downloading $asset"
    Fetch "$base/$asset" (Join-Path $tmp $asset)
    Fetch "$base/SHA256SUMS.txt" (Join-Path $tmp 'SHA256SUMS.txt')

    $line = Select-String -Path (Join-Path $tmp 'SHA256SUMS.txt') -Pattern ('\s\*?' + [regex]::Escape($asset) + '$') | Select-Object -First 1
    if (-not $line) { throw "install.ps1: $asset not listed in SHA256SUMS.txt" }
    $expected = ($line.Line -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Path (Join-Path $tmp $asset) -Algorithm SHA256).Hash.ToLower()
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
  $sep = [IO.Path]::PathSeparator
  if (($env:Path -split $sep) -notcontains $installDir) { $env:Path = "$installDir$sep$env:Path" }
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split $sep) -notcontains $installDir) {
    $new = if ($userPath) { "$userPath$sep$installDir" } else { $installDir }
    [Environment]::SetEnvironmentVariable('Path', $new, 'User')
    Write-Host "added $installDir to your PATH (new terminals pick it up)"
  }
}
