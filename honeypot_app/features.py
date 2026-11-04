import ipaddress
from datetime import timedelta

from django.utils import timezone

from .models import Attack

# Office hours (a login outside this window counts as a "suspicious time")
OFFICE_START_HOUR = 9
OFFICE_END_HOUR = 18


def country_code(ip):
    """Country code for an IP (the model expects codes like 'IN', 'US').

    For now only local/private IPs are treated as 'IN'. Public IPs get
    'unknown' (a real GeoIP lookup can be added later).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_private or addr.is_loopback:
        return "IN"
    return "unknown"


def build_features(ip, username, payload, request_size=0, secure=False):
    """Builds the 14 ML model features from one honeypot login attempt.

    This function counts the earlier attempts of this IP in the Attack table.
    Call it BEFORE saving the current attempt.
    """
    now = timezone.now()
    hour = timezone.localtime(now).hour

    last_5_min = Attack.objects.filter(ip_address=ip, time__gte=now - timedelta(minutes=5))
    last_1_min = Attack.objects.filter(ip_address=ip, time__gte=now - timedelta(minutes=1))

    # +1 because the current attempt must be counted too (every honeypot login fails)
    failed_logins = last_5_min.count() + 1
    requests_per_minute = float(last_1_min.count() + 1)

    usernames = set(last_5_min.exclude(username="").values_list("username", flat=True))
    if username:
        usernames.add(username)
    unique_usernames = max(1, len(usernames))

    outside_office = hour < OFFICE_START_HOUR or hour >= OFFICE_END_HOUR

    return {
        "hour_of_day": hour,
        "failed_login_count_5min": failed_logins,
        "unique_usernames_targeted_5min": unique_usernames,
        "port_scan_count_10min": 0,
        "requests_per_minute": requests_per_minute,
        "login_time_deviation_flag": 1 if outside_office else 0,
        "geo_velocity_flag": 0,
        "bytes_transferred": int(request_size) or len(payload.encode("utf-8")),
        "port": 443 if secure else 80,
        "source_type": "auth",
        "event_type": "login_fail",
        "protocol": "HTTPS" if secure else "HTTP",
        "status": "fail",
        "country": country_code(ip),
    }