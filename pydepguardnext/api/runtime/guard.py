# This is the guard module for pydepguardnext, providing self-healing retry logic
# All the imports are standard library or pydepguardnext internal modules
# When v4 comes, pydepguardnext will be changed to pydepguard. 

import sys
import traceback
from pydepguardnext.api.runtime.importer import install_missing_and_retry
from pydepguardnext.api.log import logit

def run_with_repair(script_path: str, max_retries: int = 5):
    """Executes a script with self-healing retry logic."""
    for attempt in range(max_retries):
        logit.logit(f"[guard] Execution attempt {attempt + 1}/{max_retries}", level="i")
        try:
            result = install_missing_and_retry(script_path)
            return result
        except ImportError as e:
            logit.logit(f"[guard] ImportError caught: {e}", level="w")
            continue  
        except Exception as e:
            logit.logit(f"Script failed due to non-import error: {e}", level="e")
            traceback.print_exc()
            break
    logit.logit(f"Maximum retry attempts reached.", level="c")
