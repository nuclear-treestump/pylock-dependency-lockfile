import importlib.metadata
from importlib.util import find_spec
from pathlib import Path
import sysconfig
import sys
import ast
import re
from typing import List, Dict
from .depscan import ImportReference


def strip_extras(requirement: str) -> str:
    return re.split(r"[<>=!~\[]", requirement)[0].strip()



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
            transitive = [strip_extras(r) for r in requires if r and not r.startswith('extra')]
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

def resolve_symbol_dependencies(symbol_fqname: str) -> List[str]:
    parts = symbol_fqname.split('.')
    for i in reversed(range(1, len(parts))):
        module_name = ".".join(parts[:i])
        attr = parts[i]

        try:
            spec = find_spec(module_name)
            if not spec or not spec.origin or not spec.origin.endswith(".py"):
                continue

            module_path = Path(spec.origin)
            with module_path.open("r", encoding="utf-8") as f:
                module_ast = ast.parse(f.read(), filename=str(module_path))
        except Exception as e:
            continue

        for node in ast.walk(module_ast):
            if isinstance(node, ast.FunctionDef) and node.name == attr:
                deps = set()
                for inner in ast.walk(node):
                    if isinstance(inner, ast.Import):
                        for alias in inner.names:
                            deps.add(alias.name.split('.')[0])
                    elif isinstance(inner, ast.ImportFrom):
                        if inner.module:
                            deps.add(inner.module.split('.')[0])
                return sorted(deps)
    return []
