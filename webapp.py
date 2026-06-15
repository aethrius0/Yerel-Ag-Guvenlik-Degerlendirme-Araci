"""
HomeNetGuard Web Arayuzu - Flask
"""

import json
import os
import threading
from datetime import datetime
from glob import glob
from flask import Flask, render_template, request, jsonify, redirect, url_for

from modules.scanner import run_full_scan
from modules.discovery import get_local_network

app = Flask(__name__)

# Tarama durumu (global, thread-safe)
scan_status = {
    "running": False,
    "stage": "",
    "message": "",
    "progress": 0.0,
    "sub": None,
    "result": None,
    "error": None,
}


def progress_callback(stage, message, progress=None, sub=None):
    scan_status["stage"] = stage
    scan_status["message"] = message
    if progress is not None:
        scan_status["progress"] = progress
    scan_status["sub"] = sub


def save_scan(result):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/scan_{timestamp}.json"
    data = {
        "timestamp": datetime.now().isoformat(),
        "network": result.get("network"),
        "devices": result["devices"],
        "scan_results": result["scan_results"],
        "security_evaluation": result["evaluated"],
        "summary": result["summary"],
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)
    return filename


def load_history():
    files = sorted(glob("output/scan_*.json"), reverse=True)
    history = []
    for f in files:
        try:
            with open(f) as fp:
                data = json.load(fp)
                data["_filename"] = f
                history.append(data)
        except Exception:
            pass
    return history


def run_scan_thread(network, timeout, do_portscan, deep, ports):
    """Taramayi ayri thread'de calistirir."""
    global scan_status
    scan_status["running"] = True
    scan_status["error"] = None
    scan_status["result"] = None
    scan_status["progress"] = 0.0

    try:
        result = run_full_scan(
            network=network or None,
            timeout=timeout,
            do_portscan=do_portscan,
            deep=deep,
            ports=ports or None,
            progress_callback=progress_callback,
        )
        scan_status["result"] = result
        save_scan(result)
    except Exception as e:
        scan_status["error"] = str(e)
    finally:
        scan_status["running"] = False
        scan_status["progress"] = 1.0


# ============= ROUTES =============

@app.route("/")
def index():
    try:
        network = get_local_network()
    except Exception:
        network = "192.168.1.0/24"
    return render_template("index.html", default_network=network)


@app.route("/scan/start", methods=["POST"])
def start_scan():
    if scan_status["running"]:
        return jsonify({"error": "Zaten bir tarama devam ediyor"}), 400

    data = request.json
    network = data.get("network", "")
    timeout = int(data.get("timeout", 2))
    do_portscan = data.get("do_portscan", True)
    deep = data.get("deep", False)
    ports = data.get("ports", "")

    thread = threading.Thread(
        target=run_scan_thread,
        args=(network, timeout, do_portscan, deep, ports),
        daemon=True,
    )
    thread.start()

    return jsonify({"status": "started"})


@app.route("/scan/status")
def get_scan_status():
    return jsonify({
        "running": scan_status["running"],
        "stage": scan_status["stage"],
        "message": scan_status["message"],
        "progress": scan_status["progress"],
        "sub": scan_status["sub"],
        "done": not scan_status["running"] and scan_status["result"] is not None,
        "error": scan_status["error"],
    })


@app.route("/dashboard")
def dashboard():
    result = scan_status.get("result")
    if not result:
        history = load_history()
        if history:
            latest = history[0]
            result = {
                "devices": latest.get("devices", []),
                "scan_results": latest.get("scan_results", []),
                "evaluated": latest.get("security_evaluation", []),
                "summary": latest.get("summary", {}),
                "network": latest.get("network", ""),
            }
    return render_template("dashboard.html", result=result)


@app.route("/history")
def history():
    scans = load_history()
    return render_template("history.html", scans=scans)


@app.route("/history/load/<int:idx>")
def load_scan(idx):
    scans = load_history()
    if idx < len(scans):
        scan = scans[idx]
        scan_status["result"] = {
            "devices": scan.get("devices", []),
            "scan_results": scan.get("scan_results", []),
            "evaluated": scan.get("security_evaluation", []),
            "summary": scan.get("summary", {}),
            "network": scan.get("network", ""),
        }
    return redirect(url_for("dashboard"))


@app.route("/api/result")
def api_result():
    return jsonify(scan_status.get("result") or {})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
