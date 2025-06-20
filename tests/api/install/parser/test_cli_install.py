from pydepguardnext.api.install.parser.cli_install import parse_cli_input
from pydepguardnext.api.install.parser.common import ParsedDependency

def test_parse_single_package():
    result = parse_cli_input("flask")
    print(result)
    assert len(result) == 1
    assert result[0].name == "flask"
    assert result[0].version is None
    assert result[0].source == "cli"

def test_parse_package_with_version():
    result = parse_cli_input("pandas==2.2.3")
    print(result)
    assert result[0].name == "pandas"
    assert result[0].version == "==2.2.3"

def test_parse_multiple_packages():
    result = parse_cli_input("flask pandas==2.2.3 yaml")
    print(result)
    assert len(result) == 3
    assert result[1].name == "pandas"
    assert result[1].version == "==2.2.3"

def test_handles_caret_and_tilde_versions():
    result = parse_cli_input("fastapi~=0.95.2 click^8.0.0")
    print(result)
    assert result[0].version == "~=0.95.2"
    assert result[1].version == "^8.0.0"
