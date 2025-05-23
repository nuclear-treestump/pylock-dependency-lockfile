import importlib.metadata
import sysconfig
import sys
from typing import List, Dict
from .depscan import ImportReference


def enrich_dependencies(imports: List[ImportReference]) -> Dict[str, dict]:
    enriched = {}

    for ref in imports:
        top_package = ref.module.split('.')[0]
        if is_stdlib_module(top_package):
            continue

        try:
            dist = importlib.metadata.distribution(top_package)
            version = dist.version
            requires = dist.requires or []
            transitive = [r.split(' ', 1)[0] for r in requires if r and not r.startswith('extra')]
        except importlib.metadata.PackageNotFoundError:
            version = "unknown"
            transitive = []

        enriched[top_package] = {
            'version': version,
            'origin': f"{ref.file}:{ref.line}",
            'tree': sorted(set(transitive))
        }

    return enriched

def is_stdlib_module(module: str) -> bool:
    import importlib.util
    spec = importlib.util.find_spec(module)
    return spec is not None and 'site-packages' not in (spec.origin or '')
