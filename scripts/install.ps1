# Aegis installer for Windows (PowerShell).
#
#   irm https://raw.githubusercontent.com/denny200897/SITCON-hacker-zone/main/scripts/install.ps1 | iex
#
# Environment overrides:
#   AEGIS_REPO         owner/repo to download from (default denny200897/SITCON-hacker-zone)
#   AEGIS_VERSION      release tag to install (default: latest)
#   AEGIS_INSTALL_DIR  install directory (default: %LOCALAPPDATA%\Aegis\bin)
$ErrorActionPreference = 'Stop'

$repo = if ($env:AEGIS_REPO) { $env:AEGIS_REPO } else { 'denny200897/SITCON-hacker-zone' }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
  'ARM64' { 'arm64' }
  default { 'amd64' }
}
$asset = "aegis-windows-$arch.exe"

$url = if ($env:AEGIS_VERSION) {
  "https://github.com/$repo/releases/download/$($env:AEGIS_VERSION)/$asset"
} else {
  "https://github.com/$repo/releases/latest/download/$asset"
}

$dir = if ($env:AEGIS_INSTALL_DIR) { $env:AEGIS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Aegis\bin' }
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$target = Join-Path $dir 'aegis.exe'

Write-Host "==> Downloading $asset ..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $url -OutFile $target -UseBasicParsing

if ((Get-Item $target).Length -lt 100000) {
  Remove-Item $target -Force
  throw "downloaded file looks wrong (no release asset yet?). Check https://github.com/$repo/releases"
}

# Add the install dir to the user's PATH if it isn't already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $dir) {
  [Environment]::SetEnvironmentVariable('Path', "$userPath;$dir", 'User')
  $env:Path = "$env:Path;$dir"
  Write-Host "==> Added $dir to your PATH (open a new terminal to pick it up)." -ForegroundColor Cyan
}

Write-Host "==> Installed aegis to $target" -ForegroundColor Green
Write-Host "Get started:  aegis"
