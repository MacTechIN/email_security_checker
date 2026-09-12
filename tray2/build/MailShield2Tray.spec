# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 정의. 실행: pyinstaller build/MailShield2Tray.spec (tray/ 에서)"""

import os
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
    a.binaries,
    a.datas,
    [],
    name="MailShield2Tray",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(ICON) if ICON.exists() else None,
    version=None,
)
