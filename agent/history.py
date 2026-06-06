import json
import os
from datetime import datetime

HISTORY_FILE = "scan_history.json"

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)

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