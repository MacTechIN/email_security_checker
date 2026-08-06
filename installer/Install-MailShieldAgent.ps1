param([string]$SourcePath = "$PSScriptRoot\publish", [string]$InstallPath = "$env:ProgramFiles\MailShield\Agent")
$ErrorActionPreference = "Stop"
$serviceName = "MailShieldAgent"
$exe = Join-Path $InstallPath "MailShield.Agent.exe"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "관리자 권한이 필요합니다. PowerShell을 '관리자 권한으로 실행'한 뒤 다시 실행하십시오."
}
if (-not (Test-Path -LiteralPath $SourcePath)) { throw "Publish directory not found: $SourcePath" }
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
Copy-Item -Path (Join-Path $SourcePath '*') -Destination $InstallPath -Recurse -Force
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existing) { Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue; sc.exe delete $serviceName | Out-Null }
New-Service -Name $serviceName -BinaryPathName "`"$exe`"" -DisplayName "MailShield Agent" -Description "MailShield email security monitoring agent" -StartupType Automatic
Start-Service -Name $serviceName
Write-Host "MailShield Agent installed and started."
