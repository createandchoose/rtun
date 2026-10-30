$ErrorActionPreference = 'Stop'
$engineDir = Join-Path $env:LOCALAPPDATA 'rtun/engine/1.14.4'
$engineExe = Join-Path $engineDir 'sing-box.exe'
if (Test-Path -LiteralPath $engineExe) { Write-Output $engineExe; exit 0 }
New-Item -ItemType Directory -Force -Path $engineDir | Out-Null
$archive = Join-Path $engineDir 'engine.zip'
try {
    Invoke-WebRequest -TimeoutSec 120 -Uri 'https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip' -OutFile $archive
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($actual -ne '99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF') { throw 'Smart routing engine checksum mismatch' }
    Expand-Archive -LiteralPath $archive -DestinationPath $engineDir -Force
    $source = Join-Path $engineDir 'sing-box-1.14.4-windows-amd64/sing-box.exe'
    Copy-Item -LiteralPath $source -Destination $engineExe
    Write-Output $engineExe
} finally {
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive }
}
