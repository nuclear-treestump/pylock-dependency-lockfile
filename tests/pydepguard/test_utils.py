from pydepguard.pylock.utils import enrich_dependencies
from pydepguard.pylock.depscan import ImportReference
from pathlib import Path

def test_enrich_known_package():
    ref = ImportReference(module='requests', file='app.py', line=5, import_type='import')
    enriched = enrich_dependencies([ref])

    assert 'requests' in enriched
    info = enriched['requests']
    assert info['version'] != 'unknown'
    assert 'urllib3' in info['tree']
    assert info['origin'] == 'app.py:5'

def test_enrich_unknown_package():
    ref = ImportReference(module='thisshouldnotexist1234', file='script.py', line=1, import_type='import')
    enriched = enrich_dependencies([ref])

    assert 'thisshouldnotexist1234' in enriched
    info = enriched['thisshouldnotexist1234']
    assert info['version'] == 'unknown'
    assert info['tree'] == []
    assert info['origin'] == 'script.py:1'
