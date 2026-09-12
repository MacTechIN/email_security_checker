# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller onedir 정의 (프로세스 1개 검증용).

onefile은 부트로더가 %TEMP%에 풀어낸 뒤 자식 프로세스로 앱을 띄우므로 항상 2개가 뜬다.
onedir은 설치 폴더의 파일을 그대로 쓰고 부트로더가 같은 프로세스에서 파이썬을 실행해 1개만 뜬다.
실행: pyinstaller build/MailShield2Tray-onedir.spec --distpath dist-onedir (tray/ 에서)
"""

from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent
ICON = ROOT / "build" / "MailShield2Tray.ico"
RESOURCES = ROOT / "mailshield2" / "resources"

datas = []
if RESOURCES.exists():
    for file in RESOURCES.iterdir():
        if file.is_file():
            datas.append((str(file), "resources"))

hiddenimports = [
    "keyring.backends.Windows",
    "win32timezone",
    "pystray._win32",
    "PIL._tkinter_finder",
    "google_auth_oauthlib.flow",
    "google.auth.transport.requests",
    "windows_toasts",
]

a = Analysis(
    [str(ROOT / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["matplotlib", "numpy", "scipy", "pandas", "IPython", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="MailShield2Tray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(ICON) if ICON.exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="MailShield2Tray",
)
