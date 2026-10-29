import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "dsproject.settings")
django.setup()

from unittest.mock import patch
from django.test import Client
from django.urls import reverse
from honeypot_app.models import Attack

c = Client(HTTP_HOST="127.0.0.1")
url = reverse("login")

users = ["admin", "root", "test", "user1", "guest", "oracle",
         "postgres", "ubuntu", "support", "administrator", "demo", "pi"]

print("Test shuru...")

# Test ke time Telegram alert band rakhte hain
with patch("honeypot_app.views.send_telegram_alert"):
    for u in users:
        r = c.post(url, {"username": u, "password": "pass123"})
        print(u, "-> status", r.status_code)

print("--- Last 12 attempts (naya upar) ---")
for a in Attack.objects.order_by("-time")[:12]:
    print(a.username, "|", a.ml_label, "|", a.risk_score, "|", a.priority)