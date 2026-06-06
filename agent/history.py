import json
import os
from datetime import datetime

HISTORY_FILE = "scan_history.json"

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []

def save_scan(result):
    history = load_history()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": result.get("target"),
        "findings": result.get("findings", []),
        "summary": {
            "total": len(result.get("findings", [])),
            "critical": sum(1 for f in result["findings"] if f["severity"] == "CRITICAL"),
            "high":     sum(1 for f in result["findings"] if f["severity"] == "HIGH"),
            "medium":   sum(1 for f in result["findings"] if f["severity"] == "MEDIUM"),
            "pass":     sum(1 for f in result["findings"] if f["severity"] == "PASS"),
        }
    }
    history.append(entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)
    return entry

def get_new_findings(current_findings, history):
    if not history:
        return []
    last = history[-1]["findings"]
    last_set = {(f["check"], f["endpoint"], f["severity"]) for f in last}
    current_set = {(f["check"], f["endpoint"], f["severity"]) for f in current_findings}
    new = current_set - last_set
    return [f for f in current_findings
            if (f["check"], f["endpoint"], f["severity"]) in new
            and f["severity"] != "PASS"]


def get_finding_key(finding):
    return (finding["check"], finding["endpoint"], finding["severity"])


def get_remediated_findings(current_findings, history):
    if not history:
        return []
    last = history[-1]["findings"]
    current_set = {get_finding_key(f) for f in current_findings}
    return [
        f for f in last
        if get_finding_key(f) not in current_set and f["severity"] != "PASS"
    ]


def get_remediation_status(history):
    if len(history) < 2:
        return []

    previous = {
        get_finding_key(f): f
        for f in history[-2].get("findings", [])
        if f.get("severity") != "PASS"
    }
    current = {
        get_finding_key(f): f
        for f in history[-1].get("findings", [])
        if f.get("severity") != "PASS"
    }

    status = []

    for key, finding in previous.items():
        if key not in current:
            status.append({
                "check": finding["check"],
                "endpoint": finding["endpoint"],
                "method": finding.get("method", "N/A"),
                "severity": finding["severity"],
                "status": "RESOLVED",
                "detail": finding.get("detail", ""),
            })

    for key, finding in current.items():
        if key not in previous:
            status.append({
                "check": finding["check"],
                "endpoint": finding["endpoint"],
                "method": finding.get("method", "N/A"),
                "severity": finding["severity"],
                "status": "NEW",
                "detail": finding.get("detail", ""),
            })

    for key in sorted(set(previous.keys()) & set(current.keys())):
        finding = current[key]
        status.append({
            "check": finding["check"],
            "endpoint": finding["endpoint"],
            "method": finding.get("method", "N/A"),
            "severity": finding["severity"],
            "status": "PERSISTS",
            "detail": finding.get("detail", ""),
        })

    return status