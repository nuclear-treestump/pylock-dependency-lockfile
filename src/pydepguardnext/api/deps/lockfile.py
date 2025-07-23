from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set



@dataclass
class DepMap:
    pypi_name: str
    pypi_url: Set[str] = field(default_factory=set)
    aliases: Set[str] = field(default_factory=set)
    versions: Set[str] = field(default_factory=set)
    try_versions: Set[str] = field(default_factory=set)
    jit_versions: Set[str] = field(default_factory=set)
    transitive: Set[str] = field(default_factory=set)
    license_info: Optional[str] = None
    origins: Set[str] = field(default_factory=set)   

    def add_alias(self, name: str):
        self.aliases.add(name)

    def add_version(self, version: str, source: str = "static"):
        if source == "try":
            self.try_versions.add(version)
        elif source == "jit":
            self.jit_versions.add(version)
        else:
            self.versions.add(version)

    def add_transitive(self, pkg: str):
        self.transitive.add(pkg)

    def add_origin(self, location: str):
        self.origins.add(location)

    def merge(self, other: "DepMap"):
        assert self.pypi_name == other.pypi_name
        self.aliases.update(other.aliases)
        self.versions.update(other.versions)
        self.try_versions.update(other.try_versions)
        self.jit_versions.update(other.jit_versions)
        self.transitive.update(other.transitive)
        self.pypi_url.update(other.pypi_url)
        self.origins.update(other.origins)
        if not self.license_info and other.license_info:
            self.license_info = other.license_info

    def to_lock_entry(self) -> dict:
        return {
            "name": self.pypi_name,
            "pypi_url": sorted(self.pypi_url),
            "aliases": sorted(self.aliases),
            "versions": sorted(self.versions),
            "try_versions": sorted(self.try_versions),
            "jit_versions": sorted(self.jit_versions),
            "transitive": sorted(self.transitive),
            "license": self.license_info,
            "origins": sorted(self.origins)
        }


class DepMapRegistry:
    def __init__(self):
        self._registry: Dict[str, DepMap] = {}

    def get(self, pypi_name: str) -> DepMap:
        return self._registry.setdefault(pypi_name, DepMap(pypi_name=pypi_name))

    def all(self) -> List[DepMap]:
        return list(self._registry.values())

    def to_lockfile(self) -> List[dict]:
        return [dep.to_lock_entry() for dep in self._registry.values()]