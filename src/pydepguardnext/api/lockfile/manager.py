import json
import os
from pathlib import Path
from datetime import datetime, timezone
from pydepguardnext.api.log.logit import logit

logslug = "api.lockfile.manager"

class LockfileManager:
    def __init__(self, script_path):
        self.script_path = Path(script_path)
        self.script_name = self.script_path.stem
        self.lockfile_name = f"{self.script_name}_dep.lck"
        self.lockfile_dir = self.script_path.parent / ".pylock"
        self.lockfile_dir.mkdir(exist_ok=True)
        self.lockfile_path = self.lockfile_dir / self.lockfile_name
        self.lockfile = None

    def exists(self):
        return self.lockfile_path.exists()

    def load(self):
        with open(self.lockfile_path, 'r') as f:
            self.lockfile = json.load(f)
        return self.lockfile

    def save(self, deps_info):
        enriched_deps = {}
        for dep, info in deps_info.items():
            enriched_deps[dep] = {
                'version': info.get('version', 'unknown'),
                'origin': info.get('origin', 'unknown'),
                'tree': info.get('tree', [])
            }

        lockfile_content = {
            'meta': {
                'script': self.script_name,
                'path': str(self.script_path),
                'saved_on': datetime.now(timezone.utc).isoformat() + 'Z',
                'last_modified': int(os.path.getmtime(self.script_path))
            },
            'deps': enriched_deps
        }
        with open(self.lockfile_path, 'w') as f:
            json.dump(lockfile_content, f, indent=4)
        logit(f"Generated new lockfile: {self.lockfile_path}", "i", source=f"{logslug}.{self.save.__name__}")