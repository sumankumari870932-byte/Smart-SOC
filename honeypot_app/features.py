import ipaddress
from datetime import timedelta

from django.utils import timezone

from .models import Attack

# Office time (is se bahar ka login "suspicious time" maana jayega)
OFFICE_START_HOUR = 9
OFFICE_END_HOUR = 18


def country_code(ip):
    """IP se country ka code (model ko 'IN', 'US' jaise codes chahiye).

    Abhi sirf local/private IP ko 'IN' maanta hai. Public IP ke liye
    'unknown' deta hai (baad mein asli GeoIP lagayenge).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_private or addr.is_loopback:
        return "IN"
    return "unknown"


def build_features(ip, username, payload, request_size=0, secure=False):
    """Honeypot ke ek login attempt se ML model ke 14 features banata hai.

    Ye function Attack table mein is IP ke pichhle attempts ginta hai.
    Isse us attempt ko save karne SE PEHLE call karna hai.
    """
    now = timezone.now()
    hour = timezone.localtime(now).hour

    last_5_min = Attack.objects.filter(ip_address=ip, time__gte=now - timedelta(minutes=5))
    last_1_min = Attack.objects.filter(ip_address=ip, time__gte=now - timedelta(minutes=1))

    # +1 kyunki ye abhi wala attempt bhi ginna hai (har honeypot login fail hota hai)
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