import subprocess
import re

def parse_rsa_private_key(path: str):
    result = subprocess.run(
        ["openssl", "rsa", "-in", path, "-noout", "-text"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"OpenSSL failed: {result.stderr}")

    out = result.stdout
    n = e = d = None

    n_match = re.search(r'modulus:\n(?: {4}([0-9a-f:]+)\n)+', out, re.MULTILINE)
    if n_match:
        n_hex = "".join(n_match.group(0).splitlines()[1:]).replace(":", "").replace(" ", "")
        n = int(n_hex, 16)

    e_match = re.search(r'publicExponent: (\d+)', out)
    if e_match:
        e = int(e_match.group(1))

    d_match = re.search(r'privateExponent:\n((?: {4}[0-9a-f:]+\n)+)', out)
    if d_match:
        d_hex = "".join(d_match.group(1).splitlines()).replace(":", "").replace(" ", "")
        d = int(d_hex, 16)

    if None in (n, e, d):
        raise ValueError("Failed to parse key components")

    return e, d, n