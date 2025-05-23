import ast
from pathlib import Path
from dataclasses import dataclass

@dataclass
class ImportReference:
    module: str
    file: str
    line: int
    import_type: str 
    imported_symbols: list[str] = None  

def scan_script_for_imports(filepath: Path) -> list[ImportReference]:
    refs = []

    with open(filepath, 'r', encoding='utf-8') as f:
        try:
            tree = ast.parse(f.read(), filename=str(filepath))
        except SyntaxError as e:
            print(f"[ERROR] Failed to parse {filepath}: {e}")
            return refs

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

    return refs
