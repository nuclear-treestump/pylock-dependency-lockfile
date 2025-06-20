
import shutil
import os
from datetime import datetime

def snapshot_script(script_path):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = f".pylock-snapshot/{os.path.basename(script_path)}.{timestamp}.bak"
    os.makedirs(".pylock-snapshot", exist_ok=True)
    shutil.copy(script_path, dest)
    return dest
