

def split_name_and_version(dep_str: str) -> tuple[str, str | None]:
    """
    Handles pip/poetry style specifiers like:
    - requests
    - requests==2.31.0
    - requests>=2.0.0
    - requests^1.1.0
    - requests~=2.4

    If no specifier is found, returns the name with None as version.

    :param dep_str: Dependency string to parse
    :type dep_str: str

    :return: Tuple of (name, version)
    :rtype: tuple[str, str | None]
    """
    specifiers = ["==", ">=", "<=", "~=", "!=", "^", ">", "<"]
    for spec in specifiers:
        if spec in dep_str:
            name, version = dep_str.split(spec, 1)
            return name.strip(), f"{spec}{version.strip()}"
    return dep_str.strip(), None

