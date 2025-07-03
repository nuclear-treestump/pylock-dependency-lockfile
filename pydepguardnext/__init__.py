from os import getenv
from types import MappingProxyType
SIGSTORE_PUBKEY = MappingProxyType({
    "n": int("0x9bf8b66bdc4cf01fb6c7b69a52bdfba451da6337932ada7ba3df605c064eaf9d02b6ac891d6b334b266cb43b83678a057ef057a3a2adaf5adbec6df3ca7dc10f50e615ca99e5c1ca35a33b44e52457f165a63ca2b05b78ebd31307aa80776eed9d89aec4cff11d41a88c900a3f48c0236b524912904fda2ca47fd229ff9c19f90a1132cba3226156b42146e44eee697d763505f636b7bbb6c276731318f4d532efbcd5360ec0ca115d4d4cabcb6e824506640cfe59c8bd5a48feb0d6cf2bd297805dcffb3738d6caaad27b9ea500a59c2f891e29e6312ba695132bcd95c346a1542b15f6a64b099da0e86bb5cec2a3fd1fbf221c50126cc7159972884fe4034d", 16),
    "e": 65537
})

if getenv("PYDEP_ALLOW_UNSECURE", "0") == "1":
    print("[pydepguardnext] WARNING: Unsecured runtime. Only .standalone tools are available.")
    from . import standalone
else:
    from .bootstrap.boot import run_boot
    run_boot()
    from .bootstrap.api_gate import enforce_api_gate
    enforce_api_gate()
