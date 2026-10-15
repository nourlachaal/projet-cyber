"""Simulate a web scan against the local HTTP honeypot (lab use only)."""
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
PATHS = ["/", "/robots.txt", "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/admin",
         "/.env", "/.git/config", "/xmlrpc.php", "/backup.zip", "/api/v1/users"]

for p in PATHS:
    req = urllib.request.Request(BASE + p, headers={"User-Agent": "sqlmap/1.7 (lab-scenario)"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print(p, r.status)
    except urllib.error.HTTPError as e:
        print(p, e.code)
    except Exception as e:
        print(p, "error:", e)