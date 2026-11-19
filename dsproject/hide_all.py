"""
Run from the project root (the folder with manage.py):
    python hide_all.py
Visitors never see the password part, for every attack type.
Only a logged-in admin sees the full payload. Safe to run twice.
"""
import re
import sys
from pathlib import Path

NEW_PROP = '''    @property
    def public_payload(self):
        # What visitors may see: the username and a masked password, for every
        # attack type. Logged-in admins see self.payload directly.
        payload = self.payload or ""
        user = getattr(self, "username", "") or ""
        if user and payload.startswith(user + " "):
            password = payload[len(user) + 1:]
        else:
            parts = payload.rsplit(" ", 1)
            if len(parts) != 2:
                return payload
            user, password = parts
        if not password or set(password) == {"*"}:
            return payload
        return user + " " + "*" * min(len(password), 12)

'''

p = Path("honeypot_app/models.py")
if not p.exists():
    print("ERROR: run this from the folder that contains manage.py"); sys.exit(1)
raw = p.read_bytes().decode("utf-8")
crlf = "\r\n" in raw
t = raw.replace("\r\n", "\n")

m = re.search(r"    @property\n    def public_payload\(self\):\n(?:(?:        .*)?\n)*", t)
if not m:
    print("ERROR: public_payload not found. Run hide_payload.py first."); sys.exit(1)
t = t[:m.start()] + NEW_PROP + t[m.end():]
if crlf:
    t = t.replace("\n", "\r\n")
p.write_bytes(t.encode("utf-8"))
print("models.py: public_payload updated")
print("DONE")