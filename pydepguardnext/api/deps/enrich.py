# Uraaaaanium fever..

import importlib.metadata as md
from pydepguardnext.api.deps.lockfile import DepMap, DepMapRegistry
from pydepguardnext.api.log.logit import logit
from pydepguardnext.api.deps.version import strip_version_spec

logslug = "api.deps.enrich"

registry = DepMapRegistry()

def enrich_module(modname: str, context: str = "static") -> DepMap:
    dep = registry.get(modname)

    try:
        dist = md.distribution(modname)
        name = dist.metadata.get("Name", modname)
        dep.pypi_url.add(f"https://pypi.org/project/{name}/")
        version = dist.version
        license = dist.metadata.get("License", None)
        if not license or len(license) < 30:
            license = dist.metadata.get("License-Expression", None)
        else:
            license = "Unknown"

        if name != dep.pypi_name:
            dep.aliases.add(dep.pypi_name)
            dep.pypi_name = name

        dep.add_version(version, source=context)
        if license:
            dep.license_info = license

        requires = dist.requires or []
        transitives = {
            strip_version_spec(r)
            for r in requires
            if r and not r.startswith("extra")
        }
        for t in transitives:
            dep.add_transitive(t)

    except md.PackageNotFoundError:
        logit(f"{modname} not found", "e", source=f"{logslug}.enrich_module")
        dep.add_version("unknown", source=context)

    return dep