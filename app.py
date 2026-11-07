"""
PhishGuard - Multi-Agent Phishing Detection Platform
Autonomous 5-Agent Pipeline, Supabase / SQLite Persistence, Security Hardening & REST APIs
"""

import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from agents.orchestrator import PhishGuardOrchestrator
from agents.url_agent import UrlAgent
from agents.content_agent import ContentAgent
from agents.header_agent import HeaderAgent
from agents.threat_intel_agent import ThreatIntelAgent
from agents.ml_agent import MLAgent

import database as db
from security import (
    validate_and_sanitize_url,
    sanitize_text,
    validate_headers,
    generate_csrf_token,
    verify_csrf_token,
    apply_security_headers
)

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "phishguard-secure-secret-key-prod-94182")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB max request size (DoS defense)

# ------------------------------------------------------------------------------
# Security Rate Limiter (Flask-Limiter)
# ------------------------------------------------------------------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[os.getenv("RATELIMIT_DEFAULT", "120/minute")],
    storage_uri="memory://"
)

# Initialize the 5-Agent Orchestrator
orchestrator = PhishGuardOrchestrator()


# ------------------------------------------------------------------------------
# Security Middleware & Template Context
# ------------------------------------------------------------------------------
@app.after_request
def security_headers_middleware(response):
    """Enforce OWASP security headers on all outgoing responses."""
    return apply_security_headers(response)


@app.context_processor
def inject_security_and_db_context():
    """Make CSRF token and database engine status accessible in all Jinja templates."""
    return {
        "csrf_token": generate_csrf_token,
        "db_info": db.get_db_status()
    }


# ------------------------------------------------------------------------------
# Web Dashboard Routes
# ------------------------------------------------------------------------------
@app.route("/")
def index():
    """Main dashboard view featuring the 5-agent scanner and recent scans."""
    recent_scans = db.get_recent_scans(limit=5)
    db_status = db.get_db_status()
    stats = db.get_scan_stats()
    return render_template("index.html", recent_scans=recent_scans, db_status=db_status, stats=stats)


@app.route("/scan/url", methods=["POST"])
@limiter.limit(os.getenv("RATELIMIT_SCAN", "30/minute"))
def scan_url():
    """Handle URL scan submission with sanitization and validation."""
    # Verify CSRF token
    token = request.form.get("csrf_token")
    if not app.config.get("TESTING") and not verify_csrf_token(token):
        return render_template("index.html", error="Invalid or missing CSRF session token.", recent_scans=db.get_recent_scans(limit=5)), 400

    target_url = request.form.get("url", "")
    is_valid, cleaned_url, err_msg = validate_and_sanitize_url(target_url)

    if not is_valid:
        recent_scans = db.get_recent_scans(limit=5)
        return render_template("index.html", error=f"Security Validation Notice: {err_msg}", recent_scans=recent_scans), 400

    payload = {"url": cleaned_url}
    report = orchestrator.scan(payload)
    db.save_scan(report)
    return render_template("report.html", report=report)


@app.route("/scan/email", methods=["POST"])
@limiter.limit(os.getenv("RATELIMIT_SCAN", "30/minute"))
def scan_email():
    """Handle email body + subject + header scan submission."""
    token = request.form.get("csrf_token")
    if not app.config.get("TESTING") and not verify_csrf_token(token):
        return render_template("index.html", error="Invalid or missing CSRF session token.", recent_scans=db.get_recent_scans(limit=5)), 400

    subject = sanitize_text(request.form.get("subject", ""), max_length=500)
    body = sanitize_text(request.form.get("body", ""), max_length=50000)
    sender = sanitize_text(request.form.get("sender", ""), max_length=250)
    auth_header = sanitize_text(request.form.get("auth_header", ""), max_length=500)

    if not body and not subject:
        recent_scans = db.get_recent_scans(limit=5)
        return render_template("index.html", error="Please provide at least email subject or body text to analyze.", recent_scans=recent_scans), 400

    headers = {}
    if sender:
        headers["From"] = sender
    if auth_header:
        headers["Authentication-Results"] = auth_header

    clean_headers = validate_headers(headers)
    payload = {
        "subject": subject,
        "body": body,
        "headers": clean_headers
    }

    report = orchestrator.scan(payload)
    db.save_scan(report)
    return render_template("report.html", report=report)


@app.route("/scan/raw", methods=["POST"])
@limiter.limit(os.getenv("RATELIMIT_SCAN", "30/minute"))
def scan_raw():
    """Handle raw RFC822 / EML email message paste."""
    token = request.form.get("csrf_token")
    if not app.config.get("TESTING") and not verify_csrf_token(token):
        return render_template("index.html", error="Invalid or missing CSRF session token.", recent_scans=db.get_recent_scans(limit=5)), 400

    raw_email = sanitize_text(request.form.get("raw_email", ""), max_length=100000)
    if not raw_email:
        return redirect(url_for("index"))

    payload = {"raw_email": raw_email}
    report = orchestrator.scan(payload)
    db.save_scan(report)
    return render_template("report.html", report=report)


@app.route("/report/<scan_id>")
def view_report(scan_id):
    """View an existing scan report by ID from Supabase or SQLite."""
    # Sanitize scan_id
    clean_id = sanitize_text(scan_id, max_length=64)
    report = db.get_scan(clean_id)
    if not report:
        recent = db.get_recent_scans(limit=5)
        return render_template("index.html", error=f"Report with ID '{clean_id}' was not found in database.", recent_scans=recent), 404
    return render_template("report.html", report=report)


@app.route("/export/<scan_id>")
def export_report(scan_id):
    """Export report as downloadable JSON file."""
    clean_id = sanitize_text(scan_id, max_length=64)
    report = db.get_scan(clean_id)
    if not report:
        return jsonify({"error": "Report not found"}), 404
    
    json_str = json.dumps(report, indent=2)
    return Response(
        json_str,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=phishguard-report-{clean_id}.json"}
    )


@app.route("/history")
def history():
    """View complete scan history audit log with statistics."""
    scans = db.get_all_scans(limit=100)
    stats = db.get_scan_stats()
    db_status = db.get_db_status()
    return render_template("history.html", scans=scans, stats=stats, db_status=db_status)


@app.route("/api-docs")
def api_docs():
    """Interactive API documentation and playground."""
    return render_template("api_docs.html", db_status=db.get_db_status())


# ------------------------------------------------------------------------------
# REST API Endpoints (Version 1 - /api/v1/...)
# ------------------------------------------------------------------------------

@app.route("/api/v1/scan", methods=["POST"])
@app.route("/api/scan", methods=["POST"])
@limiter.limit(os.getenv("RATELIMIT_SCAN", "30/minute"))
def api_scan_unified():
    """
    Unified Ensemble API: Runs full 5-agent pipeline across any combination of:
    JSON: { "url": "...", "subject": "...", "body": "...", "headers": {...}, "raw_email": "..." }
    """
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json() or {}

    # Validate URL if passed
    if "url" in data and data["url"]:
        is_valid, clean_url, err = validate_and_sanitize_url(data["url"])
        if not is_valid:
            return jsonify({"error": f"Invalid URL: {err}"}), 400
        data["url"] = clean_url

    report = orchestrator.scan(data)
    db.save_scan(report)
    return jsonify(report), 200


@app.route("/api/v1/agents/url", methods=["POST"])
@limiter.limit("60/minute")
def api_agent_url():
    """Direct API for Agent 1: URL Security Inspector."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    url = data.get("url", "")
    if not url:
        return jsonify({"error": "Field 'url' is required"}), 400

    is_valid, clean_url, err = validate_and_sanitize_url(url)
    if not is_valid:
        return jsonify({"error": err}), 400

    agent = UrlAgent()
    result = agent.analyze({"url": clean_url})
    return jsonify(result.to_dict()), 200


@app.route("/api/v1/agents/content", methods=["POST"])
@limiter.limit("60/minute")
def api_agent_content():
    """Direct API for Agent 2: Social Engineering & Content Agent."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    body = sanitize_text(data.get("body", ""), max_length=50000)
    subject = sanitize_text(data.get("subject", ""), max_length=500)
    agent = ContentAgent()
    result = agent.analyze({"body": body, "subject": subject})
    return jsonify(result.to_dict()), 200


@app.route("/api/v1/agents/header", methods=["POST"])
@limiter.limit("60/minute")
def api_agent_header():
    """Direct API for Agent 3: Header & Authentication Verifier."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    headers = validate_headers(data.get("headers", {}))
    agent = HeaderAgent()
    result = agent.analyze({"headers": headers})
    return jsonify(result.to_dict()), 200


@app.route("/api/v1/agents/threat-intel", methods=["POST"])
@limiter.limit("60/minute")
def api_agent_threat_intel():
    """Direct API for Agent 4: Threat Intelligence & DNS Infrastructure."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    agent = ThreatIntelAgent()
    result = agent.analyze(data)
    return jsonify(result.to_dict()), 200


@app.route("/api/v1/agents/ml", methods=["POST"])
@limiter.limit("60/minute")
def api_agent_ml():
    """Direct API for Agent 5: ML Heuristic & Explainable Classifier."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json() or {}
    agent = MLAgent()
    result = agent.analyze(data)
    return jsonify(result.to_dict()), 200


@app.route("/api/v1/scans", methods=["GET"])
def api_get_scans():
    """Retrieve historical scan reports."""
    limit = min(int(request.args.get("limit", 20)), 100)
    scans = db.get_all_scans(limit=limit)
    return jsonify({
        "count": len(scans),
        "limit": limit,
        "scans": scans
    }), 200


@app.route("/api/v1/scans/<scan_id>", methods=["GET"])
def api_get_single_scan(scan_id):
    """Retrieve a single scan report by ID."""
    clean_id = sanitize_text(scan_id, max_length=64)
    report = db.get_scan(clean_id)
    if not report:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(report), 200


@app.route("/api/v1/stats", methods=["GET"])
def api_stats():
    """Get aggregate threat statistics from database."""
    stats = db.get_scan_stats()
    return jsonify(stats), 200


@app.route("/api/v1/health")
@app.route("/api/health")
def api_health():
    """System health and active agent pipeline status."""
    return jsonify({
        "status": "healthy",
        "service": "PhishGuard",
        "version": "2.0.0",
        "agents_count": len(orchestrator.agents),
        "agents_active": [a.name for a in orchestrator.agents],
        "database": db.get_db_status()
    }), 200


@app.route("/api/clear-history", methods=["POST"])
def api_clear_history():
    """Clear all scan history from active database."""
    token = request.form.get("csrf_token")
    if not app.config.get("TESTING") and not verify_csrf_token(token):
        return redirect(url_for("history"))
    db.clear_all_scans()
    return redirect(url_for("history"))


# ------------------------------------------------------------------------------
# Error Handlers (Defensive: never leak traceback or internal server paths)
# ------------------------------------------------------------------------------
@app.errorhandler(400)
def bad_request(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Bad request or validation failure", "status": 400}), 400
    return render_template("index.html", error="Bad request. Please check your submitted inputs.", recent_scans=db.get_recent_scans(limit=5)), 400


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Resource not found", "status": 404}), 404
    return render_template("index.html", error="Requested resource was not found.", recent_scans=db.get_recent_scans(limit=5)), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Rate limit exceeded. Please throttle requests.", "status": 429}), 429
    return render_template("index.html", error="Rate limit exceeded. Please wait a moment before sending more scan requests.", recent_scans=db.get_recent_scans(limit=5)), 429


@app.errorhandler(500)
def internal_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "An internal server error occurred.", "status": 500}), 500
    return render_template("index.html", error="An internal error occurred. Please try again later.", recent_scans=db.get_recent_scans(limit=5)), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    print(f"[*] Starting PhishGuard 5-Agent Security Platform on port {port}...")
    print(f"[*] Database: {db.get_db_status()['engine']}")
    app.run(host="0.0.0.0", port=port, debug=debug)
