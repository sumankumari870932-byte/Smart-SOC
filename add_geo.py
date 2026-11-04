"""Adds the live attacker geo-location map to the Smart SOC Live Monitor.

Run from the project root (the folder with manage.py):
    python add_geo.py
It creates honeypot_app/geo.py and patches urls.py, views.py and monitor.html.
Safe to run twice: parts that are already added are skipped.
"""
from pathlib import Path

GEO_PY = '''import ipaddress
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
'''

VIEW_IMPORT = "from .geo import lookup_ip, is_public_ip\n"

VIEW_FUNC = '''def monitor_geo(request):
    # For the map: recent attacker IPs and their approximate location
    recent = Attack.objects.order_by('-time')[:200]

    by_ip = {}
    for a in recent:  # newest first
        info = by_ip.get(a.ip_address)
        if info is None:
            by_ip[a.ip_address] = {
                'ip': a.ip_address,
                'count': 1,
                'last_type': a.attack_type,
                'ml_label': a.ml_label,
                'priority': a.priority,
                'risk': round(a.risk_score, 1),
                'status': a.status,
                'last_time': localtime(a.time).strftime('%d %b %Y, %H:%M:%S'),
            }
        else:
            info['count'] += 1

    points = []
    local_ips = []
    fetch_budget = 5  # at most 5 new lookups per request, so the page never hangs

    for ip, info in by_ip.items():
        if not is_public_ip(ip):
            local_ips.append(ip)
            continue
        geo, fetched = lookup_ip(ip, allow_fetch=fetch_budget > 0)
        if fetched:
            fetch_budget -= 1
        if geo:
            info.update(geo)
            points.append(info)

    return JsonResponse({'points': points, 'local_ips': local_ips})


'''

HEAD_TAGS = '''<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
'''

CSS = '''
/* WORLD MAP */
.map-card{
margin-bottom:25px;
}

.map-card h2{
font-size:22px;
margin-bottom:10px;
}

#map{
height:430px;
border-radius:10px;
box-shadow:0 8px 20px rgba(0,0,0,0.1);
background:#0f172a;
}

.map-note{
margin-top:8px;
font-size:13px;
color:#475569;
}

.attack-dot{
width:16px;
height:16px;
border-radius:50%;
background:#ef4444;
border:2px solid #ffffff;
animation:blinkRed 1.2s infinite;
cursor:pointer;
}

@keyframes blinkRed{
0%{box-shadow:0 0 0 0 rgba(239,68,68,0.9);opacity:1;}
70%{box-shadow:0 0 0 20px rgba(239,68,68,0);opacity:0.55;}
100%{box-shadow:0 0 0 0 rgba(239,68,68,0);opacity:1;}
}

.pop h3{
font-size:15px;
margin-bottom:4px;
}

.pop p{
font-size:13px;
margin:2px 0;
}
'''

MAP_HTML = '''<div class="map-card">
<h2>Attacker Locations (live)</h2>
<div id="map"></div>
<p class="map-note" id="mapNote">Loading map...</p>
</div>

'''

MAP_SCRIPT = '''<script>

/* WORLD MAP: attacker IP locations (red blinking dot, details on click) */
if (typeof L === "undefined") {
    document.getElementById("mapNote").textContent =
        "Map failed to load (check your internet or the Leaflet CDN). The terminal below still works.";
} else {
    const GEO_URL = "{% url 'monitor_geo' %}";
    const mapNote = document.getElementById("mapNote");

    const map = L.map("map", {worldCopyJump: true, minZoom: 2}).setView([20, 0], 2);
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        attribution: "&copy; OpenStreetMap contributors &copy; CARTO",
        subdomains: "abcd",
        maxZoom: 19
    }).addTo(map);

    const markers = {};      // ip -> marker
    let firstFit = true;

    const dotIcon = L.divIcon({
        className: "",
        html: '<div class="attack-dot"></div>',
        iconSize: [16, 16],
        iconAnchor: [8, 8]
    });

    function addLine(parent, label, value) {
        const p = document.createElement("p");
        const b = document.createElement("b");
        b.textContent = label + ": ";
        p.appendChild(b);
        p.appendChild(document.createTextNode(value));
        parent.appendChild(p);
    }

    /* The popup is built with the DOM (textContent), so no value can run as code */
    function buildPopup(p) {
        const box = document.createElement("div");
        box.className = "pop";
        const h = document.createElement("h3");
        h.textContent = p.ip;
        box.appendChild(h);

        const place = [p.city, p.region, p.country].filter(Boolean).join(", ");
        addLine(box, "Location", place || "Unknown");
        addLine(box, "Lat / Lon", p.lat + ", " + p.lon);
        if (p.isp) { addLine(box, "ISP", p.isp); }
        addLine(box, "Attacks", String(p.count));
        addLine(box, "Last attack", p.last_type + " (" + p.last_time + ")");
        addLine(box, "ML / Risk", (p.ml_label || "-") + " / " + p.risk + " (" + (p.priority || "Unknown") + ")");
        addLine(box, "Status", p.status);

        const small = document.createElement("p");
        small.style.color = "#64748b";
        small.textContent = "Approximate location from the IP (behind a VPN or proxy, the VPN location is shown).";
        box.appendChild(small);
        return box;
    }

    async function refreshMap() {
        try {
            const res = await fetch(GEO_URL, {cache: "no-store"});
            const data = await res.json();
            const seen = {};

            data.points.forEach(p => {
                seen[p.ip] = true;
                let m = markers[p.ip];
                if (!m) {
                    m = L.marker([p.lat, p.lon], {icon: dotIcon}).addTo(map);
                    m.bindPopup(buildPopup(p));
                    m.on("click", () => {
                        map.flyTo([p.lat, p.lon], Math.max(map.getZoom(), 5), {duration: 1.2});
                    });
                    markers[p.ip] = m;
                } else {
                    m.setPopupContent(buildPopup(p));
                }
            });

            /* remove dots for IPs that are no longer in the recent list */
            Object.keys(markers).forEach(ip => {
                if (!seen[ip]) {
                    map.removeLayer(markers[ip]);
                    delete markers[ip];
                }
            });

            if (firstFit && data.points.length > 0) {
                map.fitBounds(data.points.map(p => [p.lat, p.lon]), {maxZoom: 4, padding: [40, 40]});
                firstFit = false;
            }

            let note;
            if (data.points.length > 0) {
                note = data.points.length + " attacker location(s) on the map.";
            } else {
                note = "No public attacker IP on the map yet.";
            }
            if (data.local_ips.length > 0) {
                note += " Local/private IPs (cannot be placed on a map): " + data.local_ips.join(", ");
            }
            mapNote.textContent = note;
        } catch (e) {
            mapNote.textContent = "Could not load map data, retrying...";
        }
    }

    refreshMap();
    setInterval(refreshMap, 3000);
}

</script>

'''


def read(path):
    raw = path.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    return raw.replace("\r\n", "\n"), crlf


def write(path, text, crlf):
    if crlf:
        text = text.replace("\n", "\r\n")
    path.write_bytes(text.encode("utf-8"))


def insert_before(text, anchor, new, last=False):
    i = text.rfind(anchor) if last else text.find(anchor)
    if i < 0:
        return None
    return text[:i] + new + text[i:]


def insert_after_line(text, marker, new):
    i = text.find(marker)
    if i < 0:
        return None
    j = text.find("\n", i)
    j = len(text) if j < 0 else j + 1
    prefix = text[:j] if text[:j].endswith("\n") else text[:j] + "\n"
    return prefix + new + text[j:]


def patch(path, label, steps):
    p = Path(path)
    if not p.exists():
        print("SKIP (file not found):", path)
        return
    text, crlf = read(p)
    changed = False
    for name, skip_if, fn in steps:
        if skip_if in text:
            print("ALREADY DONE:", label, "-", name)
            continue
        new = fn(text)
        if new is None:
            print("FAILED      :", label, "-", name, "(anchor not found)")
            continue
        text = new
        changed = True
        print("OK          :", label, "-", name)
    if changed:
        write(p, text, crlf)


# 1) geo.py
geo_path = Path("honeypot_app/geo.py")
if geo_path.exists():
    print("ALREADY DONE: honeypot_app/geo.py exists (left unchanged)")
else:
    geo_path.write_bytes(GEO_PY.encode("utf-8"))
    print("OK          : created honeypot_app/geo.py")

# 2) urls.py
patch("honeypot_app/urls.py", "urls.py", [
    ("monitor/geo/ route", "monitor_geo",
     lambda t: insert_after_line(t, "name='monitor_data'",
                                 "    path('monitor/geo/', views.monitor_geo, name='monitor_geo'),\n")),
])

# 3) views.py
patch("honeypot_app/views.py", "views.py", [
    ("geo import", "from .geo import",
     lambda t: insert_after_line(t, "from .ml_engine import predict_event", VIEW_IMPORT)),
    ("monitor_geo view", "def monitor_geo",
     lambda t: insert_before(t, "def attackers_view", VIEW_FUNC)),
])

# 4) monitor.html
patch("templates/monitor.html", "monitor.html", [
    ("Leaflet files", "leaflet@1.9.4",
     lambda t: insert_before(t, "</head>", HEAD_TAGS)),
    ("map CSS", "WORLD MAP",
     lambda t: insert_before(t, "</style>", CSS)),
    ("map box", 'id="map"',
     lambda t: insert_before(t, '<div class="live">', MAP_HTML)),
    ("map script", "refreshMap",
     lambda t: insert_before(t, "</body>", MAP_SCRIPT, last=True)),
])

print("\nDone. Now restart the server: python manage.py runserver")