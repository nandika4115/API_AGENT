import requests

def get_token_for(base_url, login_url, creds):
    try:
        resp = requests.post(base_url + login_url, json=creds, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("token") or data.get("access_token")
    except Exception:
        return None

def check_bola(config):
    base_url = config["target"]["base_url"]
    login_url = config["auth"]["login_url"]
    findings = []

    victim_token  = get_token_for(base_url, login_url, config["auth"]["test_credentials"])
    attacker_token = get_token_for(base_url, login_url, config["auth"]["attacker_credentials"])

    if not victim_token or not attacker_token:
        findings.append({
            "check": "BOLA",
            "severity": "ERROR",
            "endpoint": "N/A",
            "method": "N/A",
            "detail": "Could not obtain tokens for both users"
        })
        return findings

    vh = {"Authorization": f"Bearer {victim_token}"}
    ah = {"Authorization": f"Bearer {attacker_token}"}

    # --- 1. IDOR on specific order ID ---
    victim_orders = requests.get(base_url + "/workshop/api/shop/orders/all",
                                 headers=vh, timeout=5)
    if victim_orders.status_code == 200:
        try:
            body = victim_orders.json()
            items = body.get("orders") or (body if isinstance(body, list) else [])
            if items:
                order_id = items[0].get("id") or items[0].get("_id")
                if order_id:
                    url = f"{base_url}/workshop/api/shop/orders/{order_id}"
                    resp = requests.get(url, headers=ah, timeout=5)
                    findings.append({
                        "check": "BOLA",
                        "severity": "CRITICAL" if resp.status_code == 200 else "PASS",
                        "endpoint": f"/workshop/api/shop/orders/{{order_id}}",
                        "method": "GET",
                        "detail": f"Attacker accessed victim order ID {order_id} — IDOR confirmed"
                                  if resp.status_code == 200
                                  else f"Blocked with {resp.status_code}"
                    })
        except Exception:
            pass

    # --- 2. Attacker access to all orders ---
    resp = requests.get(base_url + "/workshop/api/shop/orders/all",
                        headers=ah, timeout=5)
    if resp.status_code == 200:
        try:
            body = resp.json()
            items = body.get("orders") or (body if isinstance(body, list) else [])
            has_data = len(items) > 0
        except Exception:
            has_data = False

        findings.append({
            "check": "BOLA",
            "severity": "CRITICAL" if has_data else "PASS",
            "endpoint": "/workshop/api/shop/orders/all",
            "method": "GET",
            "detail": "Attacker retrieved all orders without restriction"
                      if has_data else "No data returned for attacker"
        })

    # --- 3. IDOR on victim vehicle location ---
    vehicles_resp = requests.get(base_url + "/identity/api/v2/vehicle/vehicles",
                                 headers=vh, timeout=5)
    if vehicles_resp.status_code == 200:
        try:
            vehicles = vehicles_resp.json()
            if vehicles:
                v_uuid = vehicles[0].get("uuid")
                if v_uuid:
                    url = f"{base_url}/identity/api/v2/vehicle/{v_uuid}/location"
                    resp = requests.get(url, headers=ah, timeout=5)
                    findings.append({
                        "check": "BOLA",
                        "severity": "CRITICAL" if resp.status_code == 200 else "PASS",
                        "endpoint": f"/identity/api/v2/vehicle/{{uuid}}/location",
                        "method": "GET",
                        "detail": f"Attacker accessed victim vehicle location: {resp.status_code}"
                                  + (" — GPS data exposed" if resp.status_code == 200 else "")
                    })
        except Exception:
            pass

    # --- 4. Flag 500s as info leak ---
    for ep in config["endpoints"]:
        if ep.get("auth_required"):
            try:
                r = requests.request(ep["method"], base_url + ep["path"], timeout=5)
                if r.status_code == 500:
                    findings.append({
                        "check": "Info Leak (500)",
                        "severity": "MEDIUM",
                        "endpoint": ep["path"],
                        "method": ep["method"],
                        "detail": "Returns 500 without auth — server error exposed"
                    })
            except Exception:
                pass

    return findings