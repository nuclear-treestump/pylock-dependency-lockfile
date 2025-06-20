import json
from dataclasses import dataclass
from typing import List
from pydepguard.api.install.parser.common import ParsedDependency

@dataclass
class JSONPackage:
    pkg_name: str
    pkg_version: str

def parse_json_install(raw: str) -> List[ParsedDependency]:
    """
    Parses a JSON string containing package dependencies.

    Expected JSON format:
    {
        "packages": 
            [
                { "pkg_name": "flask", "pkg_version": ">=2.0.0" },
                { "pkg_name": "requests", "pkg_version": "latest" }
            ]
    }
        
    param raw: JSON string with a "packages" list
    type raw: str

    return: List of ParsedDependency objects
    rtype: List[ParsedDependency]
    
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"[pylock] JSON decode error: {e}")

    if not isinstance(data, dict) or "packages" not in data:
        raise ValueError("[pylock] JSON must contain a 'packages' list.")

    parsed = []
    for entry in data["packages"]:
        if not isinstance(entry, dict):
            raise ValueError(f"[pylock] Invalid entry in JSON: {entry}")
        name = entry.get("pkg_name")
        version = entry.get("pkg_version", None)
        if not name:
            raise ValueError(f"[pylock] Missing pkg_name in entry: {entry}. pkg_name is required.")
        
        else:
            match (version.strip().lower() if version else ""):
                case "latest" | "any" | "none"| "null" | "undefined" | "unspecified" | "unknown" | "unversioned" | "*" :
                    version = None
                case "":
                    version = None
                case _:
                    version = str(version)

        parsed.append(
            ParsedDependency(
                name=name,
                version=version,
                source="json",
                raw=json.dumps(entry)
            )
        )
    return parsed
