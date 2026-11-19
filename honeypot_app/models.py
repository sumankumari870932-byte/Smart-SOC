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

    # --- New fields (for AI/ML) ---
    username = models.CharField(max_length=150, blank=True, default='')
    user_agent = models.CharField(max_length=300, blank=True, default='')
    ml_label = models.CharField(max_length=50, blank=True, default='')
    confidence = models.FloatField(default=0)
    risk_score = models.FloatField(default=0)
    priority = models.CharField(max_length=20, blank=True, default='')

    def __str__(self):
        return f"{self.ip_address} - {self.attack_type}"

    @property
    def public_payload(self):
        # What visitors may see: the username and a masked password, for every
        # attack type. Logged-in admins see self.payload directly.
        payload = self.payload or ""
        user = getattr(self, "username", "") or ""
        if user and payload.startswith(user + " "):
            password = payload[len(user) + 1:]
        else:
            parts = payload.rsplit(" ", 1)
            if len(parts) != 2:
                return payload
            user, password = parts
        if not password or set(password) == {"*"}:
            return payload
        return user + " " + "*" * min(len(password), 12)

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