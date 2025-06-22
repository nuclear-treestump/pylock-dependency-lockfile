from pydepguardnext.api.deps.enrich import enrich_module
import pytest

def test_enrich_module():
    # Test the enrich_module function
    result = enrich_module("requests")
    assert result.pypi_name == "requests"