"""Sends test login attempts that pretend to come from different public IPs,
so you can see the red dots on the Live Monitor map.

The server must be running:  python manage.py runserver
Run:  python test_geo.py

This is simulated traffic. 127.0.0.1 and local IPs cannot be placed on a map.
Note: if Telegram is configured in .env, you will get one alert per attempt.
"""
import requests

URL = "http://127.0.0.1:8000/login/"
TEST_IPS = {
    "8.8.8.8": "USA",
    "77.88.8.8": "Russia",
    "114.114.114.114": "China",
    "200.160.2.3": "Brazil",
    "64.6.64.6": "USA (other)",
}

for ip, place in TEST_IPS.items():
    r = requests.post(
        URL,
        data={"username": "admin' OR 1=1 --", "password": "test"},
        headers={"X-Forwarded-For": ip},
        timeout=10,
    )
    print(ip, "(" + place + ") ->", r.status_code)

print("Done. Open the Live Monitor page and watch the map.")