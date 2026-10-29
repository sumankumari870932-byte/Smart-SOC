from django.db import models

class Attack(models.Model):
    ATTACK_TYPES = [
        ('SQL Injection', 'SQL Injection'),
        ('XSS', 'XSS'),
        ('Brute Force', 'Brute Force'),
        ('Command Injection', 'Command Injection'),
        ('Directory Traversal', 'Directory Traversal'),
        ('Normal', 'Normal'),
    ]

    ip_address = models.CharField(max_length=100)
    attack_type = models.CharField(max_length=100, choices=ATTACK_TYPES, default='Normal')
    payload = models.TextField()
    target = models.CharField(max_length=200, blank=True, null=True)
    time = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, default='Blocked')

    # --- Naye fields (AI/ML ke liye) ---
    username = models.CharField(max_length=150, blank=True, default='')
    user_agent = models.CharField(max_length=300, blank=True, default='')
    ml_label = models.CharField(max_length=50, blank=True, default='')
    confidence = models.FloatField(default=0)
    risk_score = models.FloatField(default=0)
    priority = models.CharField(max_length=20, blank=True, default='')

    def __str__(self):
        return f"{self.ip_address} - {self.attack_type}"

class Attacker(models.Model):
    ip_address = models.CharField(max_length=100, unique=True)
    country = models.CharField(max_length=100, default='Unknown')
    total_attacks = models.IntegerField(default=0)
    last_activity = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip_address


class Setting(models.Model):
    email_alerts = models.BooleanField(default=True)
    blocked_ip = models.CharField(max_length=100, blank=True, null=True)
    admin_password = models.CharField(max_length=200, default='admin123')

    def __str__(self):
        return "System Settings"