# tests/api/deps/test_enrich.py

import pytest
import json as json_module
from pydepguardnext.api.deps.enrich import enrich_module
from pydepguardnext.api.deps.lockfile import DepMap

@pytest.mark.parametrize("module_name, is_missing", [
    ("requests", False),
    ("pandas", False),
    ("json", True),  # stdlib not in metadata
    ("nonexistent_mod_abcdef", True),
])
def test_enrich_module_basic(module_name, is_missing):
    result: DepMap = enrich_module(module_name)
    print(f"Enriched module: {module_name}, Result: {result}")

    assert isinstance(result, DepMap)
    assert result.pypi_name.lower() == module_name.lower()

    if is_missing:
        assert result.versions == {"unknown"}
        assert isinstance(result.transitive, set)
    else:
        assert result.versions
        assert isinstance(result.transitive, set)
