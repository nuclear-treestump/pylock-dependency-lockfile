# tests/test_walker.py

import tempfile
from pathlib import Path
import pytest
from pydepguardnext.api.deps.walker import scan_script_for_imports, ImportReference, SymbolReference

TEST_CASES = [
    ("simple_import", "import os\n"),
    ("from_import", "from math import sqrt\n"),
    ("alias_import", "import numpy as np\n"),
    ("dynamic_import", "__import__('json')\n"),
    ("try_import", "try:\n import yaml\nexcept ImportError:\n pass\n"),
    ("attribute_access", "import pandas as pd\ndf = pd.read_csv('file.csv')\n"),
    ("unbound_usage", "df = DataFrame()\n"),
    ("chained_import", "import urllib.request\n"),
    ("relative_import", "from . import utils\n"),
]

@pytest.mark.parametrize("label, script", TEST_CASES, ids=[label for label, _ in TEST_CASES])
def test_scan_script_for_imports(label, script):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py", mode='w') as tmp:
        tmp.write(script)
        script_path = Path(tmp.name)

    try:
        imports, unbound = scan_script_for_imports(script_path)

        # Basic structure validation
        assert isinstance(imports, list), f"{label}: imports not a list"
        assert isinstance(unbound, list), f"{label}: unbound not a list"
        for imp in imports:
            assert isinstance(imp, ImportReference), f"{label}: invalid import {imp}"
        for sym in unbound:
            assert isinstance(sym, SymbolReference), f"{label}: invalid unbound {sym}"

        # Optional debugging
        print(f"\n--- {label} ---")
        print("Imports:")
        for i in imports:
            print(vars(i))
        print("Unbound:")
        for u in unbound:
            print(vars(u))

    finally:
        script_path.unlink()
