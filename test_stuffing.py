import requests

URL = "http://127.0.0.1:8000/login/"

for i in range(250):
    requests.post(URL, data={"username": f"user{i}", "password": "Pass@123"})

print("done")