param([string]$ServiceName = "MailShieldAgent")
$ErrorActionPreference = "Stop"
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
if (-not $service) { throw "서비스가 설치되어 있지 않습니다: $ServiceName. 관리자 PowerShell에서 Install-MailShieldAgent.ps1를 먼저 실행하십시오." }
Write-Host "Service: $($service.Name)"
Write-Host "State: $($service.State)"
Write-Host "Start mode: $($service.StartMode)"
Write-Host "Path: $($service.PathName)"
if ($service.State -ne "Running") { throw "Service is not running" }
if ($service.StartMode -ne "Auto") { throw "Service is not configured for automatic start" }
$events = Get-WinEvent -FilterHashtable @{LogName="System"; ProviderName="Service Control Manager"; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match [regex]::Escape($ServiceName) } | Select-Object -First 5 TimeCreated, Id, LevelDisplayName, Message
if ($events) { Write-Host "Recent service events:"; $events | Format-List }
Write-Host "Service verification passed."
