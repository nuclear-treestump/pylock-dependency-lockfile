import ast
import builtins
from pathlib import Path
from dataclasses import dataclass
from pydepguardnext.api.log.logit import logit

logslug = "api.deps.walker"

@dataclass
class ImportReference:
    module: str
    file: str
    line: int
    import_type: str
    imported_symbols: list[str] = None
    context: str = "static"

@dataclass
class SymbolReference:
    name: str
    file: str
    line: int
    context: str

def should_include_module(mod: str) -> bool:
    return not (mod.startswith('_') and '.' not in mod)

alias_map = {}


def scan_script_for_imports(filepath: Path) -> tuple[list[ImportReference], list[SymbolReference]]:
    refs = []
    used_references = []
    declared_symbols = set()
    BUILTIN_SYMBOLS = set(dir(builtins))

    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read(), filename=str(filepath))
        except SyntaxError as e:
            print(f"[ERROR] Failed to parse {filepath}: {e}")
            return refs, []

    def decompose_module(name: str) -> list[str]:
        """Break 'a.b.c' into ['a', 'a.b', 'a.b.c']."""
        parts = name.split('.')
        return ['.'.join(parts[:i + 1]) for i in range(len(parts))]

    for node in ast.walk(tree):
        context_override = None

        # --- Detect if inside try/except ImportError ---
        if isinstance(node, ast.Try):
            for stmt in node.body:
                if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                    context_override = "try"

        if isinstance(node, ast.Import):
            for alias in node.names:
                module_chain = decompose_module(alias.name)
                alias_name = alias.asname or alias.name.split('.')[0]

                for mod in module_chain:
                    if mod.startswith('_') and '.' not in mod:
                        continue
                    refs.append(ImportReference(
                        module=mod,
                        file=str(filepath),
                        line=node.lineno,
                        import_type='import',
                        imported_symbols=[alias_name],
                        context="try" if node.lineno in try_import_lines else "static"
                    ))
                
                alias_map[alias_name] = alias.name
                declared_symbols.add(alias_name)

        elif isinstance(node, ast.ImportFrom):
            if node.level and not node.module:
                module = '.' * node.level
                symbols = [alias.name for alias in node.names]
                context = "relative"
            else:
                module = f"{'.' * node.level}{node.module}" if node.level else node.module
                symbols = [alias.name for alias in node.names]
                context = "relative" if node.level else (context_override or "static")

            module_chain = decompose_module(module) if not module.startswith('.') else [module]
            for mod in module_chain:
                if not should_include_module(mod):
                    continue
                refs.append(ImportReference(
                    module=mod,
                    file=str(filepath),
                    line=node.lineno,
                    import_type='from',
                    imported_symbols=symbols,
                    context=context
                ))

            declared_symbols.update(symbols)

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == '__import__':
                if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    for mod in decompose_module(node.args[0].value):
                        if not should_include_module(mod):
                            continue
                        refs.append(ImportReference(
                            module=mod,
                            file=str(filepath),
                            line=node.lineno,
                            import_type='dynamic',
                            imported_symbols=[],
                            context='dynamic'
                        ))
                    declared_symbols.add(node.args[0].value)

            elif isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name):
                    name = node.value.id
                    full_resolved = f"{alias_map.get(name, name)}.{node.attr}"
                    used_references.append(SymbolReference(
                        name=full_resolved,
                        file=str(filepath),
                        line=node.lineno,
                        context='attribute'
                    ))

        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used_references.append(SymbolReference(
                name=node.id,
                file=str(filepath),
                line=node.lineno,
                context='load'
            ))

        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            used_references.append(SymbolReference(
                name=node.value.id,
                file=str(filepath),
                line=node.lineno,
                context='attribute'
            ))

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    declared_symbols.add(target.id)

        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                    declared_symbols.add(item.optional_vars.id)

    imported_modules = {ref.module.split('.')[0] for ref in refs}
    imported_aliases = {
        sym for ref in refs if ref.imported_symbols
        for sym in ref.imported_symbols
    }
    all_imported = imported_modules.union(imported_aliases)
    all_known = all_imported.union(declared_symbols).union(BUILTIN_SYMBOLS)

    seen = set()
    unbound_symbols = []
    for ref in used_references:
        if ref.name not in all_known and ref.name not in seen:
            unbound_symbols.append(ref)
            seen.add(ref.name)

    return refs, unbound_symbols
