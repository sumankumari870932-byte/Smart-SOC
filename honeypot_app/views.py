from django.shortcuts import render, redirect
from django.http import Http404, JsonResponse
from django.db.models import Count, Q
from .models import Attack, Attacker, Setting
from .utils import detect_attack, get_country_from_ip
from django.views.decorators.csrf import csrf_exempt
from django.db.models.functions import ExtractWeekDay
from .utils import send_telegram_alert
from django.utils.timezone import now, localtime
from .features import build_features
from .ml_engine import predict_event
from datetime import datetime


# ML label -> Attack Type (only these two; other ML labels do not become an Attack Type)
ML_LABEL_TO_TYPE = {
    "brute_force": "Brute Force",
    "credential_stuffing": "Brute Force",
}


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def update_attacker(ip):
    country = get_country_from_ip(ip)
    attacker, created = Attacker.objects.get_or_create(ip_address=ip, defaults={
        'country': country,
        'total_attacks': 1
    })

    if not created:
        attacker.total_attacks += 1
        attacker.save()


def dashboard(request):
    attacks = Attack.objects.order_by('-time')[:5]

    total_attacks = Attack.objects.count()
    today = now().date()
    today_attacks = Attack.objects.filter(time__date=today).count()
    sql_count = Attack.objects.filter(attack_type='SQL Injection').count()
    brute_count = Attack.objects.filter(attack_type='Brute Force').count()
    recent_attacks = Attack.objects.order_by('-time')[:5]

    # New ML numbers
    high_risk_count = Attack.objects.filter(priority__in=['High', 'Critical']).count()
    ml_attack_count = Attack.objects.exclude(ml_label__in=['', 'normal', 'unknown']).count()

    context = {
        'attacks': attacks,
        'total_attacks': total_attacks,
        'today_attacks': today_attacks,
        'sql_count': sql_count,
        'brute_count': brute_count,
        'recent_attacks': recent_attacks,
        'high_risk_count': high_risk_count,
        'ml_attack_count': ml_attack_count,
    }
    return render(request, 'index.html', context)


def attack_list(request, category):
    # Clicking a dashboard card shows all data for that category.
    # The filters match the counts in dashboard() exactly, so the numbers agree.
    attacks = Attack.objects.order_by('-time')

    if category == 'total':
        title = 'Total Attacks'
    elif category == 'today':
        title = "Today's Attacks"
        attacks = attacks.filter(time__date=now().date())
    elif category == 'sql':
        title = 'SQL Injection'
        attacks = attacks.filter(attack_type='SQL Injection')
    elif category == 'brute':
        title = 'Brute Force'
        attacks = attacks.filter(attack_type='Brute Force')
    elif category == 'high':
        title = 'High Risk Attacks'
        attacks = attacks.filter(priority__in=['High', 'Critical'])
    elif category == 'ml':
        title = 'ML Detected Attacks'
        attacks = attacks.exclude(ml_label__in=['', 'normal', 'unknown'])
    else:
        raise Http404()

    return render(request, 'attack_list.html', {
        'title': title,
        'attacks': attacks,
        'count': attacks.count(),
    })


def parse_search_date(text):
    # Supported formats: 28 Oct 2026, 28 October 2026, 2026-10-28, 28-10-2026, 28/10/2026
    for fmt in ("%d %b %Y", "%d %B %Y", "%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            pass
    return None


def logs_view(request):
    query = request.GET.get('q', '').strip()

    attacks = Attack.objects.all()

    if query:
        condition = (
            Q(ip_address__icontains=query) |
            Q(attack_type__icontains=query) |
            Q(status__icontains=query) |
            Q(priority__icontains=query)
        )

        search_date = parse_search_date(query)
        if search_date:
            condition |= Q(time__date=search_date)

        attacks = attacks.filter(condition)

    attacks = attacks.order_by('-time')

    return render(request, 'logs.html', {
        'attacks': attacks,
        'query': query,
    })


def monitor_view(request):
    attacks = Attack.objects.order_by('-time')[:20]
    return render(request, 'monitor.html', {'attacks': attacks})


def monitor_data(request):
    # The Live Monitor requests fresh data from here every second (no page reload)
    attacks = Attack.objects.order_by('-time')[:20]
    data = [{
        'id': a.id,
        'time': localtime(a.time).strftime('%H:%M:%S'),
        'ip': a.ip_address,
        'attack_type': a.attack_type,
        'payload': a.payload,
        'ml_label': a.ml_label,
        'risk': round(a.risk_score, 1),
        'priority': a.priority,
        'status': a.status,
    } for a in attacks]
    return JsonResponse({'attacks': data})


def attackers_view(request):
    attackers = Attacker.objects.order_by('-total_attacks')
    return render(request, 'attackers.html', {'attackers': attackers})


def analysis_view(request):
    sql_count = Attack.objects.filter(attack_type='SQL Injection').count()
    xss_count = Attack.objects.filter(attack_type='XSS').count()
    brute_count = Attack.objects.filter(attack_type='Brute Force').count()
    cmd_count = Attack.objects.filter(attack_type='Command Injection').count()

    # Weekday wise attacks count
    weekday_data = (
        Attack.objects
        .annotate(weekday=ExtractWeekDay('time'))
        .values('weekday')
        .annotate(total=Count('id'))
        .order_by('weekday')
    )

    day_counts = {
        2: 0,  # Mon
        3: 0,  # Tue
        4: 0,  # Wed
        5: 0,  # Thu
        6: 0,  # Fri
        7: 0,  # Sat
        1: 0,  # Sun
    }

    for item in weekday_data:
        day_counts[item['weekday']] = item['total']

    context = {
        'sql_count': sql_count,
        'xss_count': xss_count,
        'brute_count': brute_count,
        'cmd_count': cmd_count,

        'mon': day_counts[2],
        'tue': day_counts[3],
        'wed': day_counts[4],
        'thu': day_counts[5],
        'fri': day_counts[6],
        'sat': day_counts[7],
        'sun': day_counts[1],
    }

    return render(request, 'analysis.html', context)

def settings_view(request):
    setting, created = Setting.objects.get_or_create(id=1)

    if request.method == "POST":
        email_alerts = request.POST.get('email_alerts')
        blocked_ip = request.POST.get('blocked_ip')
        admin_password = request.POST.get('admin_password')

        setting.email_alerts = True if email_alerts == 'Enabled' else False
        setting.blocked_ip = blocked_ip
        if admin_password:
            setting.admin_password = admin_password
        setting.save()

        return redirect('settings')

    return render(request, 'settings.html', {'setting': setting})

@csrf_exempt
def honeypot_login(request):
    message = ""

    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        payload = f"{username} {password}"

        ip = get_client_ip(request)
        attack_type = detect_attack(payload)

        # ML: build the features BEFORE saving this attempt
        ml = None
        try:
            features = build_features(
                ip,
                username,
                payload,
                request_size=request.META.get("CONTENT_LENGTH") or 0,
                secure=request.is_secure(),
            )
            ml = predict_event(features)
        except Exception as e:
            print("Features error:", e)

        # Keep the honeypot working even if ML fails
        if not ml:
            ml = {"label": "unknown", "confidence": 0, "risk_score": 0, "priority": "Unknown"}

        print("ML result:", ml)

        # Keyword attack found or ML priority High/Critical -> Blocked
        if attack_type != "Normal" or ml["priority"] in ("High", "Critical"):
            status = "Blocked"
        else:
            status = "Detected"

        # No keyword match, but ML caught repeated login attempts -> Brute Force
        if attack_type == "Normal" and ml["label"] in ML_LABEL_TO_TYPE:
            attack_type = ML_LABEL_TO_TYPE[ml["label"]]

        # Save the attack (with the ML result)
        Attack.objects.create(
            ip_address=ip,
            attack_type=attack_type,
            payload=payload,
            target="Login Form",
            status=status,
            username=username[:150],
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:300],
            ml_label=ml["label"],
            confidence=ml["confidence"],
            risk_score=ml["risk_score"],
            priority=ml["priority"],
        )

        update_attacker(ip)

        # Telegram alert
        msg = f"""
🚨 Honeypot Alert!

IP: {ip}
Type: {attack_type}
Payload: {payload}
Target: Login Form

🤖 ML Label: {ml['label']}
⚠️ Risk Score: {ml['risk_score']} ({ml['priority']})
"""

        send_telegram_alert(msg)

        message = "Login Failed!"

    return render(request, 'login.html', {'message': message})