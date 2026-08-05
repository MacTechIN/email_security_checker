param([string]$SourcePath = "$PSScriptRoot\publish", [string]$InstallPath = "$env:ProgramFiles\MailShield\Agent")
$ErrorActionPreference = "Stop"
$serviceName = "MailShieldAgent"
$exe = Join-Path $InstallPath "MailShield.Agent.exe"
if (-not (Test-Path -LiteralPath $SourcePath)) { throw "Publish directory not found: $SourcePath" }
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
Copy-Item -Path (Join-Path $SourcePath '*') -Destination $InstallPath -Recurse -Force
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue; sc.exe delete $serviceName | Out-Null }
New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName "MailShield Agent" -Description "MailShield email security monitoring agent" -StartupType Automatic
Start-Service -Name $serviceName
Write-Host "MailShield Agent installed and started."
