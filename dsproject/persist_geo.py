"""
Run from the project root (the folder with manage.py):
    python persist_geo.py
Makes attacker locations permanent:
  - geo.py: locations are saved in the database (table honeypot_geo_cache),
    with 3 lookup services as fallback.
  - monitor_geo view: shows ALL attackers (not only the last 200 attacks).
Safe to run twice.
"""
import re
import sys
from pathlib import Path

GEO_PY = '''import ipaddress
import time

import requests
from django.db import connection

# Locations are saved in the database, so they survive server restarts
# and are shown every day, not only on the day of the attack.
_TABLE = "honeypot_geo_cache"
_MEM = {}                 # ip -> result (fast in-memory copy)
_FAIL = {}                # ip -> time of last failed lookup
_FAIL_SECONDS = 300       # after a failure, try again after 5 minutes
_table_ready = False


def is_public_ip(ip):
    """True only for real internet IPs. False for 127.0.0.1, 192.168.x.x, 10.x.x.x."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _ensure_table():
    global _table_ready
    if _table_ready:
        return
    try:
        with connection.cursor() as cur:
            cur.execute(
                "CREATE TABLE IF NOT EXISTS " + _TABLE + " ("
                "ip VARCHAR(64) PRIMARY KEY, "
                "lat DOUBLE PRECISION, lon DOUBLE PRECISION, "
                "city VARCHAR(120), region VARCHAR(120), "
                "country VARCHAR(120), country_code VARCHAR(10), "
                "isp VARCHAR(250), saved_at DOUBLE PRECISION)"
            )
        _table_ready = True
    except Exception as e:
        print("Geo table error:", e)


def _row_to_result(row):
    return {
        "lat": row[1], "lon": row[2], "city": row[3] or "",
        "region": row[4] or "", "country": row[5] or "",
        "country_code": row[6] or "", "isp": row[7] or "",
    }


def bulk_cached(ips):
    """Returns {ip: result} for every IP already saved. One database query."""
    found = {ip: _MEM[ip] for ip in ips if ip in _MEM}
    missing = [ip for ip in ips if ip not in found]
    if not missing:
        return found
    _ensure_table()
    try:
        with connection.cursor() as cur:
            for i in range(0, len(missing), 200):
                chunk = missing[i:i + 200]
                marks = ",".join(["%s"] * len(chunk))
                cur.execute(
                    "SELECT ip, lat, lon, city, region, country, country_code, isp "
                    "FROM " + _TABLE + " WHERE ip IN (" + marks + ")", chunk
                )
                for row in cur.fetchall():
                    res = _row_to_result(row)
                    _MEM[row[0]] = res
                    found[row[0]] = res
    except Exception as e:
        print("Geo read error:", e)
    return found


def _save(ip, r):
    _ensure_table()
    try:
        with connection.cursor() as cur:
            cur.execute("DELETE FROM " + _TABLE + " WHERE ip = %s", [ip])
            cur.execute(
                "INSERT INTO " + _TABLE + " (ip, lat, lon, city, region, country, "
                "country_code, isp, saved_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [ip, r["lat"], r["lon"], r["city"], r["region"], r["country"],
                 r["country_code"], r["isp"], time.time()],
            )
    except Exception as e:
        print("Geo save error:", e)


def _from_ipwhois(ip):
    d = requests.get("https://ipwho.is/" + ip, timeout=3).json()
    if not d.get("success"):
        return None
    return {
        "lat": d["latitude"], "lon": d["longitude"],
        "city": d.get("city") or "", "region": d.get("region") or "",
        "country": d.get("country") or "", "country_code": d.get("country_code") or "",
        "isp": (d.get("connection") or {}).get("isp") or "",
    }


def _from_ipapi_co(ip):
    d = requests.get("https://ipapi.co/" + ip + "/json/", timeout=3).json()
    if d.get("error") or d.get("latitude") is None:
        return None
    return {
        "lat": d["latitude"], "lon": d["longitude"],
        "city": d.get("city") or "", "region": d.get("region") or "",
        "country": d.get("country_name") or "", "country_code": d.get("country_code") or "",
        "isp": d.get("org") or "",
    }


def _from_ip_api(ip):
    d = requests.get("http://ip-api.com/json/" + ip, timeout=3).json()
    if d.get("status") != "success":
        return None
    return {
        "lat": d["lat"], "lon": d["lon"],
        "city": d.get("city") or "", "region": d.get("regionName") or "",
        "country": d.get("country") or "", "country_code": d.get("countryCode") or "",
        "isp": d.get("isp") or "",
    }


def lookup_ip(ip, allow_fetch=True):
    """
    Approximate location of an IP.
    Returns: (result or None, fetched)  fetched=True if an internet request was made.
    Order: memory -> database -> internet (3 services, first one that works).
    A good result is saved in the database forever.
    """
    if not is_public_ip(ip):
        return None, False

    cached = bulk_cached([ip]).get(ip)
    if cached:
        return cached, False

    now = time.time()
    if now - _FAIL.get(ip, 0) < _FAIL_SECONDS or not allow_fetch:
        return None, False

    result = None
    for fn in (_from_ipwhois, _from_ipapi_co, _from_ip_api):
        try:
            result = fn(ip)
        except Exception as e:
            print("Geo lookup error (" + fn.__name__ + "):", e)
            result = None
        if result:
            break

    if result:
        _MEM[ip] = result
        _save(ip, result)
    else:
        _FAIL[ip] = now
    return result, True
'''

VIEW_FUNC = '''def monitor_geo(request):
    # For the map: ALL attacker IPs (not only recent ones) with saved locations
    from django.db.models import Count, Max
    from .geo import bulk_cached

    rows = (Attack.objects.values('ip_address')
            .annotate(total=Count('id'), last=Max('time'))
            .order_by('-last')[:500])

    by_ip = {}
    for r in rows:
        by_ip[r['ip_address']] = {'ip': r['ip_address'], 'count': r['total'], 'last': r['last']}

    # details of the newest attack of each IP
    newest = {}
    for a in Attack.objects.filter(ip_address__in=list(by_ip)).order_by('-time')[:3000]:
        if a.ip_address not in newest:
            newest[a.ip_address] = a

    public_ips = [ip for ip in by_ip if is_public_ip(ip)]
    cached = bulk_cached(public_ips)

    points = []
    local_ips = []
    fetch_budget = 5  # at most 5 new lookups per request, so the page never hangs

    for ip, info in by_ip.items():
        if not is_public_ip(ip):
            local_ips.append(ip)
            continue
        geo = cached.get(ip)
        if geo is None and fetch_budget > 0:
            geo, fetched = lookup_ip(ip, allow_fetch=True)
            if fetched:
                fetch_budget -= 1
        if not geo:
            continue
        a = newest.get(ip)
        item = {
            'ip': ip,
            'count': info['count'],
            'last_type': a.attack_type if a else '',
            'ml_label': a.ml_label if a else '',
            'priority': a.priority if a else '',
            'risk': round(a.risk_score, 1) if a else 0,
            'status': a.status if a else '',
            'last_time': localtime(info['last']).strftime('%d %b %Y, %H:%M:%S'),
        }
        item.update(geo)
        points.append(item)

    return JsonResponse({'points': points, 'local_ips': local_ips})


'''


def main():
    geo = Path("honeypot_app/geo.py")
    views = Path("honeypot_app/views.py")
    if not geo.exists() or not views.exists():
        print("ERROR: run this from the folder that contains manage.py")
        sys.exit(1)

    geo.write_bytes(GEO_PY.encode("utf-8"))
    print("geo.py updated")

    raw = views.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")

    m = re.search(r"^def monitor_geo\(request\):\n", text, re.M)
    if not m:
        print("ERROR: monitor_geo not found in views.py")
        sys.exit(1)
    nxt = re.search(r"^(def |@|class )", text[m.end():], re.M)
    end = m.end() + nxt.start() if nxt else len(text)
    new_text = text[:m.start()] + VIEW_FUNC + text[end:]

    if "from .geo import" not in new_text:
        print("ERROR: geo import missing in views.py")
        sys.exit(1)
    if crlf:
        new_text = new_text.replace("\n", "\r\n")
    views.write_bytes(new_text.encode("utf-8"))
    print("views.py monitor_geo updated")
    print("DONE")


main()