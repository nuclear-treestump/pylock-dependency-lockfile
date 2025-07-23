"""
cli_install.py

Parser for CLI-provided dependency input.

This module handles raw strings passed via:
    pylock --install flask pandas==1.5.3

It returns a list of ParsedDependency objects,
with support for lightweight, stdlib-only version parsing.

Example:
    >>> parse_cli_input("flask pandas==1.5.3")
    [ParsedDependency(name='flask', ...), ...]
"""

from pydepguardnext.api.install.parser.common import ParsedDependency
from typing import List
from pydepguardnext.api.deps.version import split_name_and_version


def parse_cli_input(input_str: str) -> List[ParsedDependency]:
    """
    Parses a CLI-style dependency list like:
        "flask pandas==1.5.3 cv2"

    :param input_str: Space-separated dependency strings
    :type input_str: str

    :return: List of ParsedDependency objects
    :rtype: List[ParsedDependency]
    """
    deps = []
    for dep in input_str.strip().split():
        name, version = split_name_and_version(dep)
        deps.append(ParsedDependency(
            name=name,
            version=version,
            source="cli",
            raw=dep
        ))
    return deps

parse_cli_input.__doc__ = parse_cli_input.__doc__.strip() 
