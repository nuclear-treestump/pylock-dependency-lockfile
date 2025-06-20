import pytest
from pydepguardnext.api.deps.version import split_name_and_version

@pytest.mark.parametrize("input_str, expected", [
    ("requests", ("requests", None)),
    ("requests==2.31.0", ("requests", "==2.31.0")),
    ("requests>=2.0.0", ("requests", ">=2.0.0")),
    ("requests<=1.5.0", ("requests", "<=1.5.0")),
    ("requests!=2.3", ("requests", "!=2.3")),
    ("requests~=2.4", ("requests", "~=2.4")),
    ("requests>1.0", ("requests", ">1.0")),
    ("requests<3.0", ("requests", "<3.0")),
    ("requests^1.1.0", ("requests", "^1.1.0")),
    ("   requests   ==   2.0.0  ", ("requests", "==2.0.0")),
    (" numpy", ("numpy", None)),
])
def test_split_name_and_version(input_str, expected):
    assert split_name_and_version(input_str) == expected