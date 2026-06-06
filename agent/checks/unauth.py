from agent.crawler import probe_endpoint

def check_unauthenticated_access(endpoints):
    findings = []

    for ep in endpoints:
        if not ep["auth_required"]:
            continue  # skip public endpoints

        # Hit the endpoint with NO token
        result = probe_endpoint(ep["url"], ep["method"])

        if "error" in result:
            continue

        status = result["status_code"]

        # If it returns 200 without a token — that's a vulnerability
        if status == 200:
            findings.append({
                "check": "Insecure Endpoint",
                "severity": "HIGH",
                "endpoint": ep["path"],
                "method": ep["method"],
                "detail": f"Returned {status} without authentication token",
            })
        else:
            findings.append({
                "check": "Insecure Endpoint",
                "severity": "PASS",
                "endpoint": ep["path"],
                "method": ep["method"],
                "detail": f"Correctly returned {status} without token",
            })

    return findings