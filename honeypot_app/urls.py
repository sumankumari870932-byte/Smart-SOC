from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('logs/', views.logs_view, name='logs'),
    path('monitor/', views.monitor_view, name='monitor'),
    path('monitor/data/', views.monitor_data, name='monitor_data'),
    path('monitor/geo/', views.monitor_geo, name='monitor_geo'),
    path('attackers/', views.attackers_view, name='attackers'),
    path('analysis/', views.analysis_view, name='analysis'),
    path('settings/', views.settings_view, name='settings'),
    path('login/', views.honeypot_login, name='login'),
    path('attacks/<str:category>/', views.attack_list, name='attack_list'),
]