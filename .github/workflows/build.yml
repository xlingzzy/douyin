# -*- mode: python -*-
import sys
from PyInstaller.utils.hooks import collect_data_files

block_cipher = None

a = Analysis(
    ['dy_PushFlow.py'],
    binaries=[],
    datas=collect_data_files('pyshark'),
    hiddenimports=[
        'pyshark.tshark.tshark_xml',
        'cytoolz',
        'lxml', 
        'psutil._psutil_windows'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)
a.datas += [('VERSION', '.', 'DATA')]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,  
    [],
    name='RTMPAuto',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_tracer=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='favicon.ico'  # 可选图标文件
)
