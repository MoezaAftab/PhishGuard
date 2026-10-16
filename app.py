"""
PhishGuard - Multi-Agent Phishing Detection & Analysis Web Application
"""

import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response
import json
from dotenv import load_dotenv

from agents.orchestrator import PhishGuardOrchestrator

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "phishguard-dev-secret-key-39182")

orchestrator = PhishGuardOrchestrator()

# In-memory storage for scan history
scan_history = []


@app.route("/")
def index():
    """Main dashboard view with scanner tabs and recent scans."""
    recent_scans = scan_history[:5]
    return render_template("index.html", recent_scans=recent_scans)


@app.route("/scan/url", methods=["POST"])
def scan_url():
    """Handle URL scan submission."""
    target_url = request.form.get("url", "").strip()
    if not target_url:
        return redirect(url_for("index"))

    payload = {"url": target_url}
    report = orchestrator.scan(payload)
    scan_history.insert(0, report)
    return render_template("report.html", report=report)


@app.route("/scan/email", methods=["POST"])
def scan_email():
    """Handle email body + subject + header scan submission."""
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    sender = request.form.get("sender", "").strip()
    auth_header = request.form.get("auth_header", "").strip()

    headers = {}
    if sender:
        headers["From"] = sender
    if auth_header:
        headers["Authentication-Results"] = auth_header

    payload = {
        "subject": subject,
        "body": body,
        "headers": headers
    }

    report = orchestrator.scan(payload)
    scan_history.insert(0, report)
    return render_template("report.html", report=report)


@app.route("/scan/raw", methods=["POST"])
def scan_raw():
    """Handle raw RFC822 / EML email paste."""
    raw_email = request.form.get("raw_email", "").strip()
    if not raw_email:
        return redirect(url_for("index"))

    payload = {"raw_email": raw_email}
    report = orchestrator.scan(payload)
    scan_history.insert(0, report)
    return render_template("report.html", report=report)


@app.route("/report/<scan_id>")
def view_report(scan_id):
    """View an existing scan report by ID."""
    report = next((r for r in scan_history if r.get("scan_id") == scan_id), None)
    if not report:
        return render_template("index.html", error=f"Report with ID {scan_id} not found.", recent_scans=scan_history[:5]), 404
    return render_template("report.html", report=report)


@app.route("/export/<scan_id>")
def export_report(scan_id):
    """Export report as JSON download."""
    report = next((r for r in scan_history if r.get("scan_id") == scan_id), None)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    json_str = json.dumps(report, indent=2)
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=phishguard-report-{scan_id}.json"}
    )


@app.route("/history")
def history():
    """View complete scan history."""
    return render_template("history.html", scans=scan_history)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    REST API endpoint for scanning payloads programmatically.
    Accepts JSON: { url?, subject?, body?, headers?, raw_email? }
    """
    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    data = request.get_json()
    report = orchestrator.scan(data)
    scan_history.insert(0, report)
    return jsonify(report), 200


@app.route("/api/clear-history", methods=["POST"])
def api_clear_history():
    """Clear all scan history."""
    global scan_history
    scan_history.clear()
    return redirect(url_for("history"))


@app.route("/api/health")
def api_health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "PhishGuard",
        "version": "1.0.0",
        "agents_available": [a.name for a in orchestrator.agents]
    })


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    print(f"[*] Starting PhishGuard Multi-Agent Security Platform on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=debug)
