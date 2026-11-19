"""
Run from the project root (the folder with manage.py):
    python hide_payload.py
Passwords are hidden for visitors. Only a logged-in admin (staff) sees them.
Safe to run twice.
"""
import re
import sys
from pathlib import Path

ATTACK_TYPES = '("SQL Injection", "XSS", "Command Injection", "Directory Traversal")'

PROPERTY = '''
    @property
    def public_payload(self):
        # What visitors may see: attack strings as they are, credentials masked.
        # Logged-in admins see self.payload directly.
        if self.attack_type in ("SQL Injection", "XSS", "Command Injection", "Directory Traversal"):
            return self.payload
        parts = (self.payload or "").rsplit(" ", 1)
        if len(parts) == 2 and parts[1] and set(parts[1]) != {"*"}:
            return parts[0] + " " + "*" * min(len(parts[1]), 12)
        return self.payload
'''


def rd(p):
    raw = p.read_bytes().decode("utf-8")
    return raw.replace("\r\n", "\n"), "\r\n" in raw


def wr(p, text, crlf):
    if crlf:
        text = text.replace("\n", "\r\n")
    p.write_bytes(text.encode("utf-8"))


def patch_models():
    p = Path("honeypot_app/models.py")
    t, crlf = rd(p)
    if "def public_payload" in t:
        print("models.py: already done")
        return
    m = re.search(r"^class Attack\(models\.Model\):\n(?:(?:    .*)?\n)*?(?=^class |\Z)", t, re.M)
    if not m:
        print("ERROR: class Attack not found"); sys.exit(1)
    block = m.group(0).rstrip("\n") + "\n"
    t = t[:m.start()] + block + PROPERTY + "\n" + t[m.end():]
    wr(p, t, crlf)
    print("models.py: public_payload added")


def patch_views():
    p = Path("honeypot_app/views.py")
    t, crlf = rd(p)
    changed = False

    old = "'payload': a.payload,"
    new = "'payload': a.payload if request.user.is_staff else a.public_payload,"
    if old in t:
        t = t.replace(old, new); changed = True
        print("views.py: live monitor payload hidden for visitors")
    elif new in t:
        print("views.py: live monitor already done")
    else:
        print("WARNING: monitor payload line not found")

    pat = re.compile(r'stored_payload = payload if attack_type != "Normal" else ')
    if pat.search(t):
        t = pat.sub("stored_payload = payload if attack_type in " + ATTACK_TYPES + " else ", t)
        changed = True
        print("views.py: Brute Force passwords are now masked when saved")
    elif "stored_payload = payload if attack_type in" in t:
        print("views.py: save masking already done")
    else:
        print("WARNING: stored_payload line not found")

    if changed:
        wr(p, t, crlf)


def patch_templates():
    pat = re.compile(r"(?<!\{% if user.is_staff %\})\{\{\s*(\w+)\.payload\s*\}\}")
    n = 0
    for f in Path("templates").rglob("*.html"):
        t, crlf = rd(f)
        new, k = pat.subn(
            lambda m: "{% if user.is_staff %}{{ " + m.group(1) + ".payload }}{% else %}{{ "
            + m.group(1) + ".public_payload }}{% endif %}", t)
        if k:
            wr(f, new, crlf)
            n += k
            print("templates/" + f.name + ": " + str(k) + " place(s) updated")
    if not n:
        print("templates: nothing to change (already done)")


for need in ("honeypot_app/models.py", "honeypot_app/views.py", "templates"):
    if not Path(need).exists():
        print("ERROR: run this from the folder that contains manage.py"); sys.exit(1)

patch_models()
patch_views()
patch_templates()
print("DONE")