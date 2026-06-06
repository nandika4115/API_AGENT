import requests

SENSITIVE_FIELDS = [
    "password", "passwd", "secret", "credit_card", "ssn",
    "cvv", "pin", "token", "private_key", "api_key",
    "otp", "security_question", "dob", "salary"
]

OVEREXPOSED_FIELDS = [
    "is_admin", "isAdmin", "role", "internal_id",
    "created_by", "updated_by", "__v", "_class"
]

def scan_response(body, path, method):
    findings = []
    if not isinstance(body, (dict, list)):
        return findings

    def flatten(obj, prefix=""):
        fields = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                fields[f"{prefix}{k}"] = v
                fields.update(flatten(v, f"{prefix}{k}."))
        elif isinstance(obj, list) and obj:
            fields.update(flatten(obj[0], prefix))
        return fields

    all_fields = flatten(body)

    for field, value in all_fields.items():
        field_lower = field.lower().split(".")[-1]

        if field_lower in SENSITIVE_FIELDS and value not in [None, "", []]:
            findings.append({
                "check": "Excessive Data Exposure",
                "severity": "CRITICAL",
                "endpoint": path,
                "method": method,
                "detail": f"Sensitive field '{field}' exposed in response"
            })

        elif field_lower in OVEREXPOSED_FIELDS and value not in [None, "", []]:
            findings.append({
                "check": "Excessive Data Exposure",
                "severity": "MEDIUM",
                "endpoint": path,
                "method": method,
                "detail": f"Internal field '{field}' exposed in response"
            })

    return findings

def check_excessive_data_exposure(config):
    base_url = config["target"]["base_url"]
    findings = []

    token = requests.post(
        base_url + config["auth"]["login_url"],
        json=config["auth"]["test_credentials"],
        timeout=5
    ).json().get("token")

    if not token:
        findings.append({
            "check": "Excessive Data Exposure",
            "severity": "ERROR",
            "endpoint": "N/A",
            "method": "N/A",
            "detail": "Could not obtain token"
        })
        return findings

    headers = {"Authorization": f"Bearer {token}"}

    endpoints_to_check = [
        ("/identity/api/v2/user/dashboard", "GET", None),
        ("/workshop/api/shop/products", "GET", None),
        ("/identity/api/v2/vehicle/vehicles", "GET", None),
        ("/workshop/api/shop/orders/all", "GET", None),
        ("/community/api/v2/community/posts/recent", "GET", None),
    ]

    for path, method, payload in endpoints_to_check:
        try:
            if method == "GET":
                resp = requests.get(base_url + path, headers=headers, timeout=5)
            else:
                resp = requests.post(base_url + path, json=payload,
                                     headers=headers, timeout=5)

            if resp.status_code == 200:
                try:
                    body = resp.json()
                    found = scan_response(body, path, method)
                    if found:
                        findings.extend(found)
                    else:
                        findings.append({
                            "check": "Excessive Data Exposure",
                            "severity": "PASS",
                            "endpoint": path,
                            "method": method,
                            "detail": "No sensitive fields detected in response"
                        })
                except Exception:
                    pass
        except Exception:
            pass

    return findings