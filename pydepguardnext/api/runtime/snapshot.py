

def snapshot_script(script_path):
    from datetime import datetime
    from os import makedirs, path
    from shutil import copy2
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = f".pylock-snapshot/{path.basename(script_path)}.{timestamp}.bak"
    makedirs(".pylock-snapshot", exist_ok=True)
    copy2(script_path, dest)
    return dest
