import sys
import sysconfig

def is_stdlib_module(module: str) -> bool:
    return module in sys.builtin_module_names or module in sysconfig.get_paths()['stdlib']

def resolve_top_level_package(module: str) -> str:
    return module.split('.')[0]
