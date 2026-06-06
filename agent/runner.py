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
from agent.history import save_scan, get_new_findings, load_history

def run_scan():
    config = load_config()
    endpoints = get_endpoints(config)

    all_findings = []
    all_findings += check_unauthenticated_access(endpoints)
    all_findings += check_broken_auth(endpoints, config)
    all_findings += check_rate_limit(endpoints, config)
    all_findings += check_parameter_tampering(endpoints, config)
    all_findings += check_bola(config)
    all_findings += check_mass_assignment(config)
    all_findings += check_jwt_none_algorithm(config)
    all_findings += check_ssrf(config)
    all_findings += check_excessive_data_exposure(config)

    result = {
        "target": config["target"]["name"],
        "findings": all_findings
    }

    history = load_history()
    new_findings = get_new_findings(all_findings, history)
    entry = save_scan(result)

    result["new_findings"] = new_findings
    result["scan_number"] = len(history) + 1

    return result

if __name__ == "__main__":
    import json
    result = run_scan()
    print(json.dumps(result, indent=2))