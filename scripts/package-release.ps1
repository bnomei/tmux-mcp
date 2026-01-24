param(
  [Parameter(Mandatory = $true)][string]$Target,
  [Parameter(Mandatory = $true)][string]$Version,
  [string]$BinName = 'tmux-mcp-rs',
  [string]$OutDir = 'dist'
)

$ErrorActionPreference = 'Stop'

$binPath = "target/$Target/release/$BinName.exe"
if (-not (Test-Path $binPath)) {
  throw "Binary not found: $binPath"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$archiveName = "$BinName-v$Version-$Target.zip"
$archivePath = Join-Path $OutDir $archiveName

try {
  Push-Location (Split-Path -Parent $binPath)
  Compress-Archive -Path "$BinName.exe" -DestinationPath $archivePath -Force
} finally {
  Pop-Location
}

$hashPath = "$archivePath.sha256"
$hash = Get-FileHash -Algorithm SHA256 -Path $archivePath
"$($hash.Hash)  $archiveName" | Out-File -FilePath $hashPath -Encoding ascii
