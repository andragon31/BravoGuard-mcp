import requests

ALLOWED_USER = "fixed-user-123"
response = requests.get("https://api.example.com/users/fixed-user-123", timeout=5)
