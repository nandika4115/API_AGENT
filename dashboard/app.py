import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO
from agent.runner import run_scan
from agent.history import load_history
from agent.reporter import export_json, export_pdf
import threading
import time
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

latest_result = {"target": "", "findings": [], "last_scan": "Never", "new_findings": []}
scan_lock = threading.Lock()

def background_scanner():
    time.sleep(65)  # wait longer than manual scan timeout
    while True:
        if not scan_lock.locked():
            with scan_lock:
                try:
                    result = run_scan()
                    result["last_scan"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    latest_result.update(result)
                    socketio.emit("scan_update", latest_result)
                except Exception as e:
                    print(f"[BG SCAN ERROR] {e}")
        time.sleep(60)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan")
def scan_now():
    if scan_lock.locked():
        return jsonify({"error": "Scan already in progress"}), 429
    def do_scan():
        with scan_lock:
            try:
                result = run_scan()
                result["last_scan"] = time.strftime("%Y-%m-%d %H:%M:%S")
                latest_result.update(result)
                socketio.emit("scan_update", latest_result)
            except Exception as e:
                print(f"[SCAN ERROR] {e}")
    t = threading.Thread(target=do_scan)
    t.start()
    return jsonify({"status": "scan started"})

@app.route("/api/results")
def results():
    return jsonify(latest_result)

@app.route("/api/history")
def history():
    return jsonify(load_history())

@app.route("/api/export/json")
def export_json_route():
    if not latest_result.get("findings"):
        return jsonify({"error": "No scan results yet"}), 400
    filename = export_json(latest_result)
    return jsonify({"file": filename})

@app.route("/api/export/pdf")
def export_pdf_route():
    if not latest_result.get("findings"):
        return jsonify({"error": "No scan results yet"}), 400
    from agent.reporter import export_pdf
    from flask import send_file
    import os
    filename = export_pdf(latest_result)
    abs_path = os.path.abspath(filename)
    return send_file(abs_path, as_attachment=True)

if __name__ == "__main__":
    t = threading.Thread(target=background_scanner, daemon=True)
    t.start()
    socketio.run(app, debug=False, port=5000, allow_unsafe_werkzeug=True)