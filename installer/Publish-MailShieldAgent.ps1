param([string]$Configuration = "Release", [string]$OutputPath = "$PSScriptRoot\publish")
$ErrorActionPreference = "Stop"
$project = Join-Path $PSScriptRoot "..\agent\MailShield.Agent\MailShield.Agent.csproj"
$dotnet = Join-Path $env:LOCALAPPDATA "MailShield\dotnet\dotnet.exe"
if (-not (Test-Path -LiteralPath $dotnet)) { $dotnet = "dotnet" }
& $dotnet publish $project -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $OutputPath
if ($LASTEXITCODE -ne 0) { throw "publish failed" }
Write-Host "Published to $OutputPath"
