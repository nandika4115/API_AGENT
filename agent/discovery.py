import requests
import yaml

def discover_from_swagger(base_url):
    endpoints = []

    # Common swagger/openapi spec paths to try
    spec_paths = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/openapi.yaml",
    "/docs/openapi.json",
    "/api/v3/openapi.json",      # petstore3
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger/doc.json",
    "/api-docs/swagger.json",
    "/v1/swagger.json",
    "/v3/openapi.json",
]

    spec = None
    spec_url = None

    for path in spec_paths:
        try:
            resp = requests.get(base_url + path, timeout=5)
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                if "yaml" in content_type or path.endswith(".yaml"):
                    spec = yaml.safe_load(resp.text)
                else:
                    spec = resp.json()
                spec_url = base_url + path
                print(f"[DISCOVERY] Found spec at {spec_url}")
                break
        except Exception:
            continue

    if not spec:
        print(f"[DISCOVERY] No OpenAPI spec found at {base_url}")
        return endpoints, None

    # Parse OpenAPI 3.x or Swagger 2.x
    paths = spec.get("paths", {})

    # Determine base path (Swagger 2.x has basePath)
    base_path = spec.get("basePath", "")

    for path, methods in paths.items():
        for method, details in methods.items():
            if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                continue

            # Check if endpoint requires auth
            security = details.get("security", spec.get("security", []))
            auth_required = len(security) > 0

            endpoints.append({
                "path": base_path + path,
                "method": method.upper(),
                "auth_required": auth_required,
                "url": base_url + base_path + path,
                "summary": details.get("summary", ""),
                "source": "swagger"
            })

    print(f"[DISCOVERY] Found {len(endpoints)} endpoints from spec")
    return endpoints, spec_url