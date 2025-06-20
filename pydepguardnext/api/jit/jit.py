# JIT Module for PyDepGuard
# This module provides Just-In-Time (JIT) import resolution capabilities.
# It attempts to import modules dynamically and can install missing packages if needed.
# If the flag --retry is enabled, it will try to restart the script after installing missing packages.
# This process is iterative and will continue until all imports are resolved or no further progress can be made.
# The time has come for ImportError to be sent to the shadow realm.

# STDLIB
import importlib
import sys
import subprocess
import ast
import inspect
from pathlib import Path

# Internal Magic
from pydepguardnext.api import errors
from pydepguardnext.api.log import logit

# External Dependencies...
# Oh wait, there are none!

# Formatting
from typing import List, Dict

# Log setup only done here for testing purposes. Will be removed when integrated.

logit.configure_logging(
    level="INFO",
    fmt="text",
    to_file="jit.log",
)

_jit_ast_check_cache = None

def _get_user_script_filename():
    for frame_info in inspect.stack():
        # Skip frames inside this package/module
        if "pydepguardnext" not in frame_info.filename:
            return frame_info.filename
    return None 

def _jit_guard(module_name, pydep_init=False):
    global _jit_ast_check_cache

    if pydep_init:
        return

    if _jit_ast_check_cache is not None:
        if not _jit_ast_check_cache:
            raise errors.JITImportSecurityError("jit_import call violates literal constraint")
        return

    filename = _get_user_script_filename()
    logit.logit(f"Checking AST for jit_import in {filename}", "d")
    if not filename:
        logit.logit("Unable to locate user script for AST scan.", "w")
        _jit_ast_check_cache = True
        return

    try:
        with open(filename, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=filename)
    except Exception as e:
        logit.logit(f"AST scan failed: {e}", "w")
        _jit_ast_check_cache = True
        return

    flagged = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'jit_import':
            if not (len(node.args) > 0 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                flagged = True
                break

    _jit_ast_check_cache = not flagged

    if flagged:
        raise errors.JITImportSecurityError("jit_import only accepts string literals as the module name."
                                              "Variables, expressions, or user input are not allowed for security reasons.")


def jit_import(module_name: str, version: str, install_missing: bool = True, pydep_init: bool = False) -> bool:
    source = __name__
    _jit_guard(module_name, pydep_init=pydep_init)

    try:
        importlib.import_module(module_name)
        return True
    except ImportError:
        if not install_missing:
            raise

        logit.logit(f"'{module_name}' not found. Installing...", "w", source=source)
        if not version or version.lower() in {"latest", "any", "none", "null", "undefined", "unspecified", "unknown", "unversioned", "*"}:
            module_string = module_name 
            logit.logit(f"No version specified. Installing latest version of '{module_name}'...", "e", source=source)
        else:
            module_string = f"{module_name}=={version}"
            logit.logit(f"Installing '{module_name}' with version '{version}'...", "i", source=source)
        subprocess.check_call([sys.executable, "-m", "pip", "install", module_string])
        logit.logit(f"Installed '{module_name}=={version}' successfully.", "i", source=source)
        return True
