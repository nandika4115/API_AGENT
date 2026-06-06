import requests
from agent.crawler import probe_endpoint

def get_valid_token(base_url, config):
    auth_cfg = config.get("auth", {})
    login_url = base_url + auth_cfg.get("login_url", "")
    creds = auth_cfg.get("test_credentials", {})

    try:
        resp = requests.post(login_url, json=creds, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            # crAPI returns token here
            return data.get("token") or data.get("access_token")
    except Exception as e:
        print(f"[AUTH] Login failed: {e}")
    return None

def check_broken_auth(endpoints, config):
    base_url = config["target"]["base_url"]
    findings = []

    bad_tokens = [
        ("expired_token", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxMDAwLCJleHAiOjEwMDF9.invalidsig"),
        ("malformed_token", "not.a.token"),
        ("empty_bearer",    ""),
    ]

    protected = [ep for ep in endpoints if ep["auth_required"]]

    for ep in protected:
        for token_name, token_value in bad_tokens:
            headers = {"Authorization": f"Bearer {token_value}"} if token_value else {"Authorization": "Bearer"}
            result = probe_endpoint(ep["url"], ep["method"], headers=headers)

            if "error" in result:
                continue

            status = result["status_code"]

            if status == 200:
                findings.append({
                    "check": "Broken Authentication",
                    "severity": "CRITICAL",
                    "endpoint": ep["path"],
                    "method": ep["method"],
                    "detail": f"Accepted {token_name} and returned 200",
                })
            else:
                findings.append({
                    "check": "Broken Authentication",
                    "severity": "PASS",
                    "endpoint": ep["path"],
                    "method": ep["method"],
                    "detail": f"Correctly rejected {token_name} with {status}",
                })

    return findings