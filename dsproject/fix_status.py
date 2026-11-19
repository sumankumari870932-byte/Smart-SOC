"""
Run from the project root (the folder with manage.py):
    python fix_status.py
Fixes the Blocked/Detected inconsistency for Brute Force. Safe to run twice.
"""
import sys
from pathlib import Path

OLD = 'if attack_type != "Normal" or ml["priority"] in ("High", "Critical"):'
NEW = 'if attack_type not in ("Normal", "Brute Force") or ml["priority"] in ("High", "Critical"):'

p = Path("honeypot_app/views.py")
if not p.exists():
    print("ERROR: run this from the folder that contains manage.py"); sys.exit(1)
raw = p.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
t = raw.replace("\r\n", "\n")

if NEW in t:
    print("Already done")
elif t.count(OLD) == 1:
    t = t.replace(OLD, NEW)
    if crlf:
        t = t.replace("\n", "\r\n")
    p.write_bytes(t.encode("utf-8"))
    print("views.py: status rule updated")
else:
    print("ERROR: status line not found"); sys.exit(1)
print("DONE")