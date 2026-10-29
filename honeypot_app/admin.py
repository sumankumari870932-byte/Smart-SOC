from django.contrib import admin
from .models import Attack, Attacker, Setting

admin.site.register(Attack)
admin.site.register(Attacker)
admin.site.register(Setting)