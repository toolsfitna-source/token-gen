# -*- mode: python ; coding: utf-8 -*-
import os

_root   = r'C:\Users\amrou\PycharmProjects\Raider'
_tg     = os.path.join(_root, 'Tools', 'TokenGen')
_jar    = os.path.join(_root, 'okhttp-proxy', 'okhttp-proxy.jar')
_libs   = os.path.join(_root, 'okhttp-proxy', 'libs')
_solver = os.path.join(_tg, 'solver')
_hsj    = os.path.join(_root, 'HSJ reverse', 'Hcaptcha-hsj-reverse-main', 'hsj.js')

block_cipher = None

_datas = [
    (os.path.join(_tg, 'config'), 'config'),
    (_jar, 'okhttp-proxy'),
    (_libs, 'okhttp-proxy/libs'),
    (_solver, 'solver'),
]
if os.path.isfile(_hsj):
    _datas.append((_hsj, 'HSJ reverse/Hcaptcha-hsj-reverse-main'))

a = Analysis(
    [os.path.join(_tg, 'main.py')],
    pathex=[_tg],
    binaries=[],
    datas=_datas,
    hiddenimports=[
        'websocket', 'websocket._abnf', 'websocket._core',
        'websocket._exceptions', 'websocket._http', 'websocket._socket',
        'websocket._ssl_compat', 'websocket._url', 'websocket._utils',
        'tls_client',
        'requests', 'certifi', 'urllib3', 'zstandard',
        'charset_normalizer', 'idna',
        'Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES',
        'Crypto.Random', 'Crypto.Util', 'Crypto.Util.Padding',
        'solver', 'solver.hcaptcha_solver', 'solver.phone_profile',
        'solver.phone_motion', 'solver.patch_hsj_events', 'solver.hsj_runner',
        'solver.core', 'solver.core.config', 'solver.core.checkcaptcha_helper',
        'solver.core.hsj', 'solver.core.motion', 'solver.core.foox1_pool',
        'http_client',
    ],
    hookspath=[],
    excludes=['torch', 'torchvision', 'cv2', 'numpy', 'matplotlib',
              'PIL', 'playwright', 'selenium', 'seleniumwire',
              'cloudscraper', 'curl_cffi'],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True,
          name='tokengen', debug=False, strip=False, upx=False, console=True)
coll = COLLECT(exe, a.binaries, a.zipfiles, a.datas,
               strip=False, upx=False, name='tokengen')
