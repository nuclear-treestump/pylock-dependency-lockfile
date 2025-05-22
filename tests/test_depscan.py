import tempfile
from pathlib import Path
from pylock.depscan import scan_script_for_imports, ImportReference

def write_temp_script(code: str) -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as tmp:
        tmp.write(code)
        return Path(tmp.name)

def print_refs(label: str, results: list[ImportReference]):
    print(f"\n[{label}] Found {len(results)} imports:")
    for ref in results:
        print(f"  - {ref.import_type.upper()}: {ref.module} (line {ref.line}) symbols={ref.imported_symbols}")

def test_basic_import_scan():
    code = "import os\nimport sys\n"
    tmp_path = write_temp_script(code)

    results = scan_script_for_imports(tmp_path)
    print_refs("BASIC IMPORT", results)

    modules = {r.module for r in results}
    assert {'os', 'sys'}.issubset(modules)
    assert all(isinstance(r, ImportReference) for r in results)

def test_from_import_multiple_symbols():
    code = "from math import sqrt, pow"
    tmp_path = write_temp_script(code)

    results = scan_script_for_imports(tmp_path)
    print_refs("FROM IMPORT MULTIPLE", results)

    assert len(results) == 1
    assert results[0].module == 'math'
    assert sorted(results[0].imported_symbols) == ['pow', 'sqrt']

def test_import_with_alias():
    code = "import pandas as pd"
    tmp_path = write_temp_script(code)

    results = scan_script_for_imports(tmp_path)
    print_refs("IMPORT WITH ALIAS", results)

    assert len(results) == 1
    assert results[0].module == 'pandas'
    assert results[0].imported_symbols == ['pd']

def test_relative_import():
    code = "from . import localmod"
    tmp_path = write_temp_script(code)

    results = scan_script_for_imports(tmp_path)
    print_refs("RELATIVE IMPORT", results)

    assert len(results) == 1
    assert results[0].module == '.'
    assert 'localmod' in results[0].imported_symbols

def test_dynamic_import_builtin():
    code = "__import__('json')"
    tmp_path = write_temp_script(code)

    results = scan_script_for_imports(tmp_path)
    print_refs("DYNAMIC BUILTIN", results)

    assert len(results) == 1
    assert results[0].module == 'json'
    assert results[0].import_type == 'dynamic'

def test_importlib_dynamic_import():
    code = "import importlib\nimportlib.import_module('collections')"
    tmp_path = write_temp_script(code)

    results = scan_script_for_imports(tmp_path)
    print_refs("IMPORTLIB DYNAMIC", results)

    dynamic = [r for r in results if r.import_type == 'dynamic']
    assert any(r.module == 'collections' for r in dynamic)

def test_bad_syntax_graceful_fail():
    code = "def broken(:"
    tmp_path = write_temp_script(code)

    results = scan_script_for_imports(tmp_path)
    print_refs("BAD SYNTAX", results)

    assert results == []
