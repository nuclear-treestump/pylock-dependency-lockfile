import ast
import builtins
from pathlib import Path
from dataclasses import dataclass
from pydepguardnext.api.log.logit import logit

logslug = "api.deps.walker"

from typing import Literal


@dataclass
class ImportReference:
    module: str
    file: str
    line: int
    import_type: str  # 'import', 'from', or 'dynamic'
    imported_symbols: list[str] = None
    context: str = "static"  # 'static', 'dynamic', 'try', 'relative'

@dataclass
class SymbolReference:
    name: str
    file: str
    line: int
    context: str  # 'load', 'attribute'

def should_include_module(mod: str) -> bool:
    return not (mod.startswith('_') and '.' not in mod)

def scan_script_for_imports(filepath: Path) -> tuple[list[ImportReference], list[SymbolReference]]:
    refs = []
    used_references = []
    declared_symbols = set()
    BUILTIN_SYMBOLS = set(dir(builtins))
    alias_map = {}

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=str(filepath))
    except SyntaxError as e:
        logit(f"[ERROR] Failed to parse {filepath}: {e}", "e", source=logslug)
        return refs, []

    def decompose_module(name: str) -> list[str]:
        return ['.'.join(name.split('.')[:i + 1]) for i in range(len(name.split('.')))]

    # Detect try/except import context
    try_import_lines = {
        stmt.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Try)
        for stmt in node.body
        if isinstance(stmt, (ast.Import, ast.ImportFrom))
    }

    for node in ast.walk(tree):
        # import x
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_chain = decompose_module(alias.name)
                alias_name = alias.asname or alias.name.split('.')[0]
                for mod in module_chain:
                    if should_include_module(mod):
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

        # from x import y
        elif isinstance(node, ast.ImportFrom):
            module = (
                f"{'.' * node.level}{node.module}" if node.level and node.module else
                '.' * node.level if node.level else ''
            )
            symbols = [alias.name for alias in node.names]
            context = "relative" if node.level else ("try" if node.lineno in try_import_lines else "static")
            module_chain = decompose_module(module) if not module.startswith('.') else [module]
            for mod in module_chain:
                if should_include_module(mod):
                    refs.append(ImportReference(
                        module=mod,
                        file=str(filepath),
                        line=node.lineno,
                        import_type='from',
                        imported_symbols=symbols,
                        context=context
                    ))
            declared_symbols.update(symbols)

        # dynamic imports
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == '__import__':
                if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    for mod in decompose_module(node.args[0].value):
                        if should_include_module(mod):
                            refs.append(ImportReference(
                                module=mod,
                                file=str(filepath),
                                line=node.lineno,
                                import_type='dynamic',
                                imported_symbols=[],
                                context='dynamic'
                            ))
                    declared_symbols.add(node.args[0].value)

            elif isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    name = node.func.value.id
                    full_resolved = f"{alias_map.get(name, name)}.{node.func.attr}"
                    used_references.append(SymbolReference(
                        name=full_resolved,
                        file=str(filepath),
                        line=node.lineno,
                        context='attribute'
                    ))

        # name usage
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            used_references.append(SymbolReference(
                name=node.id,
                file=str(filepath),
                line=node.lineno,
                context='load'
            ))

        # attr usage
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            used_references.append(SymbolReference(
                name=node.value.id,
                file=str(filepath),
                line=node.lineno,
                context='attribute'
            ))

        # variable declarations
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    declared_symbols.add(target.id)

        # with ... as ...
        elif isinstance(node, ast.With):
            for item in node.items:
                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                    declared_symbols.add(item.optional_vars.id)

    # Final analysis
    imported_modules = {ref.module.split('.')[0] for ref in refs}
    imported_aliases = {sym for ref in refs if ref.imported_symbols for sym in ref.imported_symbols}
    all_known = imported_modules | imported_aliases | declared_symbols | BUILTIN_SYMBOLS

    seen = set()
    unbound_symbols = [
        ref for ref in used_references
        if ref.name not in all_known and ref.name not in seen and not seen.add(ref.name)
    ]

    return refs, unbound_symbols

ScanMode = Literal['full', 'top', 'dynamic', 'try_deps']

def scan_script_by_mode(filepath: Path, mode: ScanMode = 'full') -> list[ImportReference]:
    all_refs, _ = scan_script_for_imports(filepath)

    match mode:
        case 'full':
            return all_refs
        case 'top':
            return [r for r in all_refs if r.context == 'static' and r.import_type in {'import', 'from'}]
        case 'dynamic':
            return [r for r in all_refs if r.context in {'static', 'dynamic'} and r.import_type in {'import', 'from', 'dynamic'}]
        case 'try_deps':
            return [r for r in all_refs if r.context == 'try']
        case _:
            return all_refs