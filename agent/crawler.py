import requests
import yaml

def load_config(config_path="config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def get_endpoints(config):
    base_url = config["target"]["base_url"]
    endpoints = []
    for ep in config["endpoints"]:
        endpoints.append({
            "url": base_url + ep["path"],
            "method": ep["method"],
            "auth_required": ep.get("auth_required", False),
            "path": ep["path"]
        })
    return endpoints

def probe_endpoint(url, method, headers=None, json=None):
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers or {},
            json=json,
            timeout=5
        )
        return {
            "status_code": response.status_code,
            "body": response.text[:300],
            "headers": dict(response.headers)
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}