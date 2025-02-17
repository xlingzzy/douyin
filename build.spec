# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/dypushflow.py'],
    pathex=[],
    binaries=[],
    datas=[('src/favicon.ico', '.')],
    hiddenimports=[
        'pyshark.capture',
        'pyshark.tshark.tshark',
        'win32timezone',
        'psutil'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='RTMPHunter',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='src/favicon.ico',
    uac_admin=True
)
