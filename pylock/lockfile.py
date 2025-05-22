import json
import os
from pathlib import Path

class LockfileManager:
    def __init__(self, script_path):
        self.script_path = script_path
        self.script_name = Path(script_path).stem
        self.lockfile_name = f"{self.script_name}_dep.lck"
        self.lockfile = None

    def exists(self):
        return os.path.exists(self.lockfile_name)

    def load(self):
        with open(self.lockfile_name, 'r') as f:
            self.lockfile = json.load(f)
        return self.lockfile

    def save(self, deps_info):
        lockfile_content = {
            'meta': {
                'script': self.script_name,
                'hash': 'NYI',
                'last_modified': int(os.path.getmtime(self.script_path))
            },
            'deps': deps_info
        }
        with open(self.lockfile_name, 'w') as f:
            json.dump(lockfile_content, f, indent=4)
        print(f"Generated new lockfile: {self.lockfile_name}")