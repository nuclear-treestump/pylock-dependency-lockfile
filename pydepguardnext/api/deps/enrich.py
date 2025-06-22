# Uraaaaanium fever..

import importlib.metadata as md
from math import dist
from pydepguardnext.api.deps.lockfile import DepMap, DepMapRegistry
from pydepguardnext.api.log.logit import logit

logslug = "api.deps.enrich"

registry = DepMapRegistry()

def enrich_module(modname: str) -> DepMap:
    try:
        dist = md.distribution(modname)
        version = dist.version
        name = dist.metadata["Name"]
        license = dist.metadata.get("License", None)
        requires = dist.requires or []
        for key, value in dist.metadata.items():
            print(f"{key}: {value}")
    except md.PackageNotFoundError:
        logit(f"{modname} not found", "e", source=f"{logslug}.{enrich_module.__name__}")
        return DepMap(pypi_name=modname)