import ast
import builtins
from pathlib import Path
from dataclasses import dataclass

@dataclass
class ImportReference:
    module: str
    file: str
    line: int
    import_type: str
    imported_symbols: list[str] = None

@dataclass
class SymbolReference:
    name: str
    file: str
    line: int
    context: str

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

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                refs.append(ImportReference(
                    module=alias.name,
                    file=str(filepath),
                    line=node.lineno,
                    import_type='import',
                    imported_symbols=[alias.asname] if alias.asname else []
                ))
                declared_symbols.add(alias.asname or alias.name.split('.')[0])

        elif isinstance(node, ast.ImportFrom):
            if node.level and not node.module:
                module = '.' * node.level
                symbols = [alias.name for alias in node.names]
            else:
                module = f"{'.' * node.level}{node.module}" if node.level else node.module
                symbols = [alias.name for alias in node.names]

            refs.append(ImportReference(
                module=module,
                file=str(filepath),
                line=node.lineno,
                import_type='from',
                imported_symbols=symbols
            ))
            declared_symbols.update(symbols)

        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == '__import__':
                if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    refs.append(ImportReference(
                        module=node.args[0].value,
                        file=str(filepath),
                        line=node.lineno,
                        import_type='dynamic',
                        imported_symbols=[]
                    ))
                    declared_symbols.add(node.args[0].value)

            elif isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module':
                if hasattr(node.func.value, 'id') and node.func.value.id == 'importlib':
                    if len(node.args) >= 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        refs.append(ImportReference(
                            module=node.args[0].value,
                            file=str(filepath),
                            line=node.lineno,
                            import_type='dynamic',
                            imported_symbols=[]
                        ))
                        declared_symbols.add(node.args[0].value)

        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                used_references.append(SymbolReference(
                    name=node.id,
                    file=str(filepath),
                    line=node.lineno,
                    context='load'
                ))

        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
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
