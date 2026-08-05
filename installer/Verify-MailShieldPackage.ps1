param([string]$PackagePath = "$PSScriptRoot\publish")
$ErrorActionPreference = "Stop"

$required = @("MailShield.Agent.exe", "appsettings.json")
if (-not (Test-Path -LiteralPath $PackagePath -PathType Container)) { throw "Package directory not found: $PackagePath" }
foreach ($name in $required) {
    $path = Join-Path $PackagePath $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file missing: $name" }
}

$exe = Get-Item -LiteralPath (Join-Path $PackagePath "MailShield.Agent.exe")
if ($exe.Length -lt 1MB) { throw "Agent executable is unexpectedly small: $($exe.Length) bytes" }
$hash = Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256
Write-Host "Package OK"
Write-Host "Executable: $($exe.FullName)"
Write-Host "Size: $($exe.Length) bytes"
Write-Host "SHA256: $($hash.Hash)"
Write-Host "Code signing must be verified before production distribution."
