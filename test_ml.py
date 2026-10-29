from honeypot_app.ml_engine import predict_event

normal = {
    "hour_of_day": 10, "failed_login_count_5min": 0,
    "unique_usernames_targeted_5min": 1, "port_scan_count_10min": 0,
    "requests_per_minute": 1.5, "login_time_deviation_flag": 0,
    "geo_velocity_flag": 0, "bytes_transferred": 1800, "port": 443,
    "source_type": "auth", "event_type": "login_success",
    "protocol": "HTTPS", "status": "success", "country": "IN",
}

attack = {
    "hour_of_day": 3, "failed_login_count_5min": 25,
    "unique_usernames_targeted_5min": 1, "port_scan_count_10min": 0,
    "requests_per_minute": 40.0, "login_time_deviation_flag": 1,
    "geo_velocity_flag": 0, "bytes_transferred": 300, "port": 22,
    "source_type": "auth", "event_type": "login_fail",
    "protocol": "SSH", "status": "fail", "country": "RU",
}

print("NORMAL :", predict_event(normal))
print("ATTACK :", predict_event(attack))