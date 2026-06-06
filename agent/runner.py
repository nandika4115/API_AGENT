from agent.crawler import load_config, get_endpoints
from agent.checks.unauth import check_unauthenticated_access
from agent.checks.auth import check_broken_auth
from agent.checks.ratelimit import check_rate_limit
from agent.checks.params import check_parameter_tampering
from agent.checks.bola import check_bola
from agent.checks.mass_assignment import check_mass_assignment
from agent.checks.jwt_none import check_jwt_none_algorithm
from agent.checks.ssrf import check_ssrf
from agent.checks.data_exposure import check_excessive_data_exposure
from agent.history import (
    save_scan,
    get_new_findings,
    get_remediated_findings,
    get_remediation_status,
    load_history,
)
from agent.discovery import discover_from_swagger

def run_scan(override_url=None):
    config = load_config()

    if override_url:
        config["target"]["base_url"] = override_url.rstrip("/")
        config["target"]["name"] = override_url.rstrip("/")

    base_url = config["target"]["base_url"]

    discovered, spec_url = discover_from_swagger(base_url)
    if discovered:
        endpoints = discovered
        external_target = True
    else:
        endpoints = get_endpoints(config)
        external_target = False

    all_findings = []
    all_findings += check_unauthenticated_access(endpoints)

    if not external_target:
        # These checks require valid credentials configured in config.yaml
        all_findings += check_broken_auth(endpoints, config)
        all_findings += check_rate_limit(endpoints, config)
        all_findings += check_parameter_tampering(endpoints, config)
        all_findings += check_bola(config)
        all_findings += check_mass_assignment(config)
        all_findings += check_jwt_none_algorithm(config)
        all_findings += check_ssrf(config)
        all_findings += check_excessive_data_exposure(config, endpoints=endpoints)

    history = load_history()
    new_findings = get_new_findings(all_findings, history)
    remediated_findings = get_remediated_findings(all_findings, history)
    remediation_status = get_remediation_status(history + [{"findings": all_findings}])

    result = {
        "target": config["target"]["name"],
        "findings": all_findings,
        "spec_url": spec_url,
        "endpoint_count": len(endpoints),
        "discovery_mode": "swagger" if discovered else "config",
        "new_findings": new_findings,
        "remediated_findings": remediated_findings,
        "remediation_status": remediation_status,
    }

    save_scan(result)
    result["scan_number"] = len(history) + 1
    return result

if __name__ == "__main__":
    import json
    result = run_scan()
    print(json.dumps(result, indent=2))