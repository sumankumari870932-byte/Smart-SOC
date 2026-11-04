"""Gets the Smart SOC project ready for a public free deployment (Render).

Run from the project root (the folder with manage.py):
    python make_public.py

What it does:
  1. settings.py  -> replaced (old copy saved as settings.py.bak). Reads the host, secret key,
                     debug flag and DATABASE_URL from environment variables.
  2. views.py     -> Settings page needs an admin login; normal visitors' passwords are
                     masked (****) before they are saved or shown on the public dashboard.
  3. login.html   -> adds a "do not enter real credentials" notice.
  4. requirements.txt -> adds gunicorn, whitenoise, dj-database-url, psycopg.
  5. build.sh, .gitattributes, .gitignore -> deployment helpers.
Safe to run twice.
"""
from pathlib import Path

SETTINGS = '''"""
Django settings for the Smart SOC project (dsproject).

Secrets and deployment values come from environment variables (or a local .env file,
which is never committed to GitHub).
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file(path):
    """Tiny .env reader (no extra package needed). The .env file is never committed to GitHub."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file(BASE_DIR / ".env")


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "django-insecure-dev-only-change-me")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get("DJANGO_DEBUG", "True") == "True"

# Hosts: DJANGO_ALLOWED_HOSTS="a.com,b.com" plus the Render hostname (set automatically by Render).
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",") if h.strip()]
CSRF_TRUSTED_ORIGINS = []

_render_host = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
if _render_host:
    ALLOWED_HOSTS.append(_render_host)
    CSRF_TRUSTED_ORIGINS.append("https://" + _render_host)

if not DEBUG:
    # Refuse to start in production with the development secret key.
    if SECRET_KEY.startswith("django-insecure"):
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured("Set DJANGO_SECRET_KEY to a long random value when DJANGO_DEBUG is False.")
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'honeypot_app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# WhiteNoise serves the static files (images, logo) when DEBUG is False.
# It is only used if installed, so local development works without it.
try:
    import whitenoise  # noqa: F401
    MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')
except ImportError:
    pass

ROOT_URLCONF = 'dsproject.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'dsproject.wsgi.application'


# Database: SQLite locally. If DATABASE_URL is set (for example a free Neon Postgres),
# that database is used, so attack logs survive restarts on a free host.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

_database_url = os.environ.get("DATABASE_URL")
if _database_url:
    import dj_database_url
    DATABASES['default'] = dj_database_url.parse(_database_url, conn_max_age=600, ssl_require=True)


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# Internationalization
LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'   # filled by: python manage.py collectstatic

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'
'''

BUILD_SH = '''#!/usr/bin/env bash
# Build script for Render. Exit on the first error.
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate

# Create the admin user from environment variables (skip quietly if it already exists).
python manage.py createsuperuser --noinput || echo "Admin user already exists, skipping."
'''

LOGIN_NOTICE = '''
<p style="margin-top:14px;font-size:12px;color:#94a3b8;text-align:center;max-width:320px;">
This is a security research honeypot. Every attempt is logged. Please do not enter real usernames or passwords.
</p>
'''

REQ_LINES = ["gunicorn", "whitenoise", "dj-database-url", "psycopg[binary]"]


def read(path):
    raw = Path(path).read_bytes().decode("utf-8")
    return raw.replace("\r\n", "\n"), "\r\n" in raw


def write(path, text, crlf):
    if crlf:
        text = text.replace("\n", "\r\n")
    Path(path).write_bytes(text.encode("utf-8"))


def insert_after_line(text, marker, new):
    i = text.find(marker)
    if i < 0:
        return None
    j = text.find("\n", i)
    j = len(text) if j < 0 else j + 1
    return text[:j] + new + text[j:]


def replace_once(text, old, new):
    if old not in text:
        return None
    return text.replace(old, new, 1)


# ---- 1. settings.py
sp = Path("dsproject/settings.py")
if sp.exists():
    old, crlf = read(sp)
    if "RENDER_EXTERNAL_HOSTNAME" in old:
        print("ALREADY DONE: settings.py")
    else:
        Path("dsproject/settings.py.bak").write_bytes(sp.read_bytes())
        write(sp, SETTINGS, crlf)
        print("OK          : settings.py replaced (backup: dsproject/settings.py.bak)")
else:
    print("SKIP: dsproject/settings.py not found")

# ---- 2. views.py
vp = Path("honeypot_app/views.py")
if vp.exists():
    text, crlf = read(vp)
    steps = [
        ("admin-only Settings import", "staff_member_required",
         lambda t: insert_after_line(t, "from django.shortcuts import render, redirect",
                                     "from django.contrib.admin.views.decorators import staff_member_required\n")),
        ("admin-only Settings page", "@staff_member_required\ndef settings_view",
         lambda t: replace_once(t, "def settings_view(request):", "@staff_member_required\ndef settings_view(request):")),
        ("mask normal passwords", "stored_payload =",
         lambda t: insert_after_line(
             t, "attack_type = detect_attack(payload)",
             "        # Public site: never keep or show a visitor's password in plain text.\n"
             "        # Inputs that look like attacks are stored as they are.\n"
             "        stored_payload = payload if attack_type != \"Normal\" else f\"{username} {'*' * min(len(password), 12)}\"\n")),
        ("save masked payload", "payload=stored_payload",
         lambda t: replace_once(t, "payload=payload,", "payload=stored_payload,")),
        ("alert masked payload", "Payload: {stored_payload}",
         lambda t: replace_once(t, "Payload: {payload}", "Payload: {stored_payload}")),
    ]
    changed = False
    for name, skip_if, fn in steps:
        if skip_if in text:
            print("ALREADY DONE:", "views.py -", name)
            continue
        new = fn(text)
        if new is None:
            print("FAILED      :", "views.py -", name, "(anchor not found)")
            continue
        text = new
        changed = True
        print("OK          :", "views.py -", name)
    if changed:
        write(vp, text, crlf)
else:
    print("SKIP: honeypot_app/views.py not found")

# ---- 3. login.html
lp = Path("templates/login.html")
if lp.exists():
    text, crlf = read(lp)
    if "security research honeypot" in text:
        print("ALREADY DONE: login.html notice")
    else:
        new = insert_after_line(text, "</form>", LOGIN_NOTICE)
        if new is None:
            print("FAILED      : login.html (</form> not found)")
        else:
            write(lp, new, crlf)
            print("OK          : login.html notice added")
else:
    print("SKIP: templates/login.html not found")

# ---- 4. requirements.txt
rp = Path("requirements.txt")
if rp.exists():
    text, crlf = read(rp)
    have = {l.split("==")[0].split("[")[0].strip().lower() for l in text.splitlines() if l.strip()}
    add = [r for r in REQ_LINES if r.split("[")[0].lower() not in have]
    if add:
        if not text.endswith("\n"):
            text += "\n"
        write(rp, text + "\n".join(add) + "\n", crlf)
        print("OK          : requirements.txt added", ", ".join(add))
    else:
        print("ALREADY DONE: requirements.txt")
else:
    print("SKIP: requirements.txt not found (run: pip freeze > requirements.txt)")

# ---- 5. helper files
Path("build.sh").write_bytes(BUILD_SH.encode("utf-8"))   # always LF line endings
print("OK          : build.sh written")
Path(".gitattributes").write_bytes(b"*.sh text eol=lf\n")
print("OK          : .gitattributes written")

gp = Path(".gitignore")
gtext = gp.read_bytes().decode("utf-8") if gp.exists() else ""
if "staticfiles/" not in gtext:
    if gtext and not gtext.endswith("\n"):
        gtext += "\n"
    gp.write_bytes((gtext + "staticfiles/\n").encode("utf-8"))
    print("OK          : .gitignore now ignores staticfiles/")

print("\nDone. Test locally first: python manage.py runserver")