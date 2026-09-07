<#
.SYNOPSIS
  MailShield Tray를 단일 exe로 빌드하고 Inno Setup 설치기를 만든다.

.DESCRIPTION
  1. 단위 테스트 실행 (-SkipTests로 생략)
  2. 아이콘 생성
  3. PyInstaller --onefile --noconsole → dist\MailShieldTray.exe
  4. Inno Setup(ISCC.exe) → output\MailShieldTray-Setup.exe (-SkipInstaller로 생략)

  실행 위치와 무관하게 동작한다. 관리자 권한이 필요하지 않다.
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$TrayRoot = Split-Path -Parent $PSScriptRoot
Set-Location $TrayRoot
$env:PYTHONUTF8 = "1"

Write-Host "== MailShield Tray 빌드 ($TrayRoot)" -ForegroundColor Cyan

Write-Host "-- 의존성 확인"
python -m pip install -q -r requirements-dev.txt

if (-not $SkipTests) {
    Write-Host "-- 단위 테스트"
    python -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "단위 테스트 실패" }
}

Write-Host "-- 아이콘 생성"
python build\make_icon.py build\MailShieldTray.ico

Write-Host "-- PyInstaller"
if (Test-Path dist) { Remove-Item dist -Recurse -Force }
if (Test-Path build\pyi) { Remove-Item build\pyi -Recurse -Force }
python -m PyInstaller --clean --noconfirm --distpath dist --workpath build\pyi build\MailShieldTray.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 실패" }

$exe = Join-Path $TrayRoot "dist\MailShieldTray.exe"
if (-not (Test-Path $exe)) { throw "exe가 생성되지 않았습니다: $exe" }
$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "   $exe ($size MB)" -ForegroundColor Green

Write-Host "-- 실행 파일 자체 점검 (--version, 콘솔 없는 exe라 출력은 없고 종료 코드만 확인)"
& $exe --version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "exe 실행 점검 실패 (종료 코드 $LASTEXITCODE)" }
Write-Host "   OK"

if (-not $SkipInstaller) {
    $iscc = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) {
        Write-Warning "Inno Setup 6(ISCC.exe)을 찾지 못해 설치기 생성을 건너뜁니다. https://jrsoftware.org/isdl.php"
    } else {
        Write-Host "-- Inno Setup"
        if (-not (Test-Path output)) { New-Item -ItemType Directory output | Out-Null }
        & $iscc /Qp "build\MailShieldTray.iss"
        if ($LASTEXITCODE -ne 0) { throw "Inno Setup 실패" }
        Get-ChildItem output\MailShieldTray-Setup*.exe | ForEach-Object {
            Write-Host "   $($_.FullName) ($([math]::Round($_.Length / 1MB, 1)) MB)" -ForegroundColor Green
        }
    }
}

Write-Host "== 완료" -ForegroundColor Cyan
