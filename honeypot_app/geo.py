import ipaddress
import time

import requests

# Cache lookups so the same IP is not sent to the internet again and again.
# (The cache is empty after a server restart. That is fine.)
_CACHE = {}               # ip -> (saved_at, result or None)
_OK_SECONDS = 24 * 3600   # remember a successful result for 24 hours
_FAIL_SECONDS = 300       # after a failure, try again after 5 minutes


def is_public_ip(ip):
    """True only for real internet IPs. False for 127.0.0.1, 192.168.x.x, 10.x.x.x."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def lookup_ip(ip, allow_fetch=True):
    """
    Finds the approximate location of an IP (free service: ipwho.is).
    Returns: (result, fetched)
      result  -> {'lat','lon','city','region','country','country_code','isp'} or None
      fetched -> True if this call made an internet request
    """
    if not is_public_ip(ip):
        return None, False

    now = time.time()
    hit = _CACHE.get(ip)
    if hit:
        saved_at, result = hit
        ttl = _OK_SECONDS if result else _FAIL_SECONDS
        if now - saved_at < ttl:
            return result, False

    if not allow_fetch:
        return None, False

    result = None
    try:
        data = requests.get("https://ipwho.is/" + ip, timeout=3).json()
        if data.get("success"):
            result = {
                "lat": data["latitude"],
                "lon": data["longitude"],
                "city": data.get("city") or "",
                "region": data.get("region") or "",
                "country": data.get("country") or "",
                "country_code": data.get("country_code") or "",
                "isp": (data.get("connection") or {}).get("isp") or "",
            }
    except Exception as e:
        print("Geo lookup error:", e)

    _CACHE[ip] = (now, result)
    return result, True
