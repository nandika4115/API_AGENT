import requests
import time

def check_rate_limit(endpoints, config):
    base_url = config["target"]["base_url"]
    findings = []

    # Test on login endpoint — most critical to rate limit
    login_url = base_url + config["auth"]["login_url"]
    
    TOTAL_REQUESTS = 20
    success_count = 0
    blocked_count = 0
    status_codes = []

    for i in range(TOTAL_REQUESTS):
        try:
            resp = requests.post(
                login_url,
                json={"email": f"fake{i}@test.com", "password": "wrongpass"},
                timeout=5
            )
            status_codes.append(resp.status_code)
            if resp.status_code in [429, 403]:
                blocked_count += 1
            else:
                success_count += 1
        except Exception:
            pass
        time.sleep(0.05)  # 50ms between requests

    if blocked_count == 0:
        findings.append({
            "check": "Rate Limit Bypass",
            "severity": "HIGH",
            "endpoint": config["auth"]["login_url"],
            "method": "POST",
            "detail": f"Sent {TOTAL_REQUESTS} requests, never got 429. Statuses: {list(set(status_codes))}",
        })
    else:
        findings.append({
            "check": "Rate Limit Bypass",
            "severity": "PASS",
            "endpoint": config["auth"]["login_url"],
            "method": "POST",
            "detail": f"Rate limited after {success_count} requests (got 429/403 {blocked_count} times)",
        })

    return findings