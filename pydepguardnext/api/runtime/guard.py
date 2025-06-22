# This is the guard module for pydepguardnext, providing self-healing retry logic
# All the imports are standard library or pydepguardnext internal modules
# When v4 comes, pydepguardnext will be changed to pydepguard. 

import sys
import traceback
import time
import hashlib
import json
from pathlib import Path
from pydepguardnext import PyDepBullshitDetectionError
from pydepguardnext.api.runtime.importer import install_missing_and_retry
from pydepguardnext.api.log.logit import logit

g_time = 0

logslug = "api.runtime.guard"

def run_with_repair(script_path: str, max_retries: int = 5):
    """Executes a script with self-healing retry logic."""
    global g_time
    g_time = time.time()
    logit(f"PyDepGuard self-healing guard started at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(g_time))}", "i", source=f"{logslug}.{run_with_repair.__name__}")
    logit(f"Running script with self-healing logic: {script_path}", "i", source=f"{logslug}.{run_with_repair.__name__}")
    for attempt in range(max_retries):
        logit(f"Execution attempt {attempt + 1}/{max_retries}", "i", source=f"{logslug}.{run_with_repair.__name__}")
        try:
            is_cached = False
            cached_result = load_cached_result(script_path)
            if cached_result:
                logit(f"Using cached result for {script_path}", "i", source=f"{logslug}.{run_with_repair.__name__}")
                is_cached = True
            result, deps = install_missing_and_retry(script_path, timecheck=g_time, cached=is_cached)
            if not is_cached:
                sha = _compute_sha256(script_path)
                cache_data = {
                    "sha256": sha,
                    "deps": deps  
                }
                save_cache(script_path, cache_data)
                logit(f"Cache saved for {script_path} with SHA {sha}", "i", source=f"{logslug}.{run_with_repair.__name__}")
            else:
                logit(f"Using cached lock data for {script_path}", "i", source=f"{logslug}.{run_with_repair.__name__}")
            return result
        except ImportError as e:
            logit(f"ImportError caught: {e}", "w", source=f"{logslug}.{run_with_repair.__name__}")
            continue  
        except Exception as e:
            logit(f"Script failed due to non-import error: {e}", "e", source=f"{logslug}.{run_with_repair.__name__}")
            traceback.print_exc()
            break
    logit(f"Maximum retry attempts reached.", "c", source=f"{logslug}.{run_with_repair.__name__}")


def _compute_sha256(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()
    

def get_lockfile_path(script_path: str, sha: str) -> Path:
    script = Path(script_path).resolve()
    lock_name = f"{script.stem}_{sha[-10:]}.pydeplock"
    return script.parent.parent / lock_name


def save_cache(script_path: str, lock_data: dict):
    sha = _compute_sha256(script_path)
    lock_path = get_lockfile_path(script_path, sha)
    payload = {
        "sha256": sha,
        "deps": lock_data  
    }
    lockfile_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    with open(lock_path, "w") as f:
        json.dump(payload, f, indent=4)
        f.write("\n")  # Ensure the first JSON object ends
        f.write(f"---PYDEPGUARD LOCKFILE---\n")  # Delimiter line
        json.dump({"lockfile_sha256": lockfile_hash}, f, indent=4)

def load_cached_result(script_path: str):
    sha = _compute_sha256(script_path)
    lock_path = get_lockfile_path(script_path, sha)
    if lock_path.exists():
        with open(lock_path, "r") as f:
            content = f.read()
        parts = content.split("---PYDEPGUARD LOCKFILE---")
        if len(parts) != 2:
            return None
        try:
            payload = json.loads(parts[0])
            lockfile_hash_obj = json.loads(parts[1])
        except Exception:
            return None
        payload_sha = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if payload_sha != lockfile_hash_obj.get("lockfile_sha256"):
            logit(f"LOCKFILE MISMATCH!", "f", source=f"{logslug}.{load_cached_result.__name__}")
            logit(f"Environment Compromised.", "f", source=f"{logslug}.{load_cached_result.__name__}")
            raise PyDepBullshitDetectionError(expected=payload_sha, found=lockfile_hash_obj.get("lockfile_sha256"))
        if payload.get("sha256") == sha and "lockfile_sha256" in lockfile_hash_obj and lockfile_hash_obj["lockfile_sha256"] == payload_sha:
            logit(f"Lockfile SHA256 matches, using cached result.", "i", source=f"{logslug}.{load_cached_result.__name__}")
            logit(f"JIT resolution not needed, using cached deps.", "i", source=f"{logslug}.{load_cached_result.__name__}")
            return payload
    return None
