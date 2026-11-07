"""
Database Module for PhishGuard
Provides transparent dual-mode persistence:
1. Supabase Cloud PostgreSQL (when SUPABASE_URL and SUPABASE_KEY are provided)
2. Local SQLite database (phishguard.db) as a zero-setup fallback

Completely immune to SQL injection via parameterized queries and ORM calls.
"""

import os
import json
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "").strip()

# SQLite fallback file path
SQLITE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishguard.db")

_supabase_client = None
_db_mode = "sqlite"

# Attempt initializing Supabase if credentials exist
if SUPABASE_URL and SUPABASE_KEY and "your-project" not in SUPABASE_URL:
    try:
        from supabase import create_client, Client
        _supabase_client: Optional[Client] = create_client(SUPABASE_URL, SUPABASE_KEY)
        _db_mode = "supabase"
    except Exception as e:
        print(f"[!] Warning: Failed to initialize Supabase client ({e}). Falling back to SQLite.")
        _supabase_client = None
        _db_mode = "sqlite"


def init_sqlite_db():
    """Ensure SQLite database schema is created."""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_preview TEXT NOT NULL,
            overall_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            verdict_badge_class TEXT NOT NULL,
            threat_summary TEXT NOT NULL,
            report_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


# Always initialize SQLite on import so it's ready as fallback
init_sqlite_db()


def get_db_status() -> Dict[str, str]:
    """Return active database engine and connection state."""
    return {
        "engine": "Supabase Cloud" if _db_mode == "supabase" and _supabase_client else "SQLite (Local)",
        "mode": _db_mode,
        "location": SUPABASE_URL if _db_mode == "supabase" else SQLITE_DB_PATH
    }


def _extract_target_meta(report: Dict[str, Any]) -> tuple:
    """Extract human-readable target preview and type."""
    input_prev = report.get("input_preview", {})
    if input_prev.get("url"):
        return "url", input_prev["url"]
    elif input_prev.get("subject"):
        return "email", input_prev["subject"]
    elif input_prev.get("body_snippet"):
        return "content", input_prev["body_snippet"]
    return "general", "Security Assessment Payload"


def save_scan(report: Dict[str, Any]) -> bool:
    """
    Persist scan report to active database (Supabase or SQLite).
    """
    scan_id = report.get("scan_id")
    if not scan_id:
        return False

    target_type, target_preview = _extract_target_meta(report)
    timestamp = report.get("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"))
    overall_score = float(report.get("overall_score", 0.0))
    verdict = report.get("verdict", "SAFE")
    badge_class = report.get("verdict_badge_class", "badge-safe")
    threat_summary = report.get("threat_summary", "")

    # Try Supabase if active
    if _db_mode == "supabase" and _supabase_client:
        try:
            payload = {
                "scan_id": scan_id,
                "timestamp": timestamp,
                "target_type": target_type,
                "target_preview": target_preview[:250],
                "overall_score": overall_score,
                "verdict": verdict,
                "verdict_badge_class": badge_class,
                "threat_summary": threat_summary,
                "report_json": report,
            }
            res = _supabase_client.table("scans").upsert(payload).execute()
            if res.data:
                return True
        except Exception as e:
            print(f"[!] Supabase save error: {e}. Falling back to SQLite.")

    # SQLite fallback
    try:
        conn = sqlite3.connect(SQLITE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO scans 
            (scan_id, timestamp, target_type, target_preview, overall_score, verdict, verdict_badge_class, threat_summary, report_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            timestamp,
            target_type,
            target_preview[:250],
            overall_score,
            verdict,
            badge_class,
            threat_summary,
            json.dumps(report)
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[!] SQLite save error: {e}")
        return False


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full scan report by ID."""
    if not scan_id:
        return None

    # Try Supabase
    if _db_mode == "supabase" and _supabase_client:
        try:
            res = _supabase_client.table("scans").select("report_json").eq("scan_id", scan_id).execute()
            if res.data and len(res.data) > 0:
                raw_report = res.data[0]["report_json"]
                return raw_report if isinstance(raw_report, dict) else json.loads(raw_report)
        except Exception as e:
            print(f"[!] Supabase retrieve error: {e}. Checking SQLite.")

    # SQLite
    try:
        conn = sqlite3.connect(SQLITE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception as e:
        print(f"[!] SQLite get_scan error: {e}")

    return None


def get_recent_scans(limit: int = 10) -> List[Dict[str, Any]]:
    """Get the most recent scans for dashboard display."""
    return get_all_scans(limit=limit)


def get_all_scans(limit: int = 100) -> List[Dict[str, Any]]:
    """Get all historical scans up to limit."""
    # Try Supabase
    if _db_mode == "supabase" and _supabase_client:
        try:
            res = _supabase_client.table("scans").select("report_json").order("created_at", desc=True).limit(limit).execute()
            if res.data:
                reports = []
                for item in res.data:
                    raw = item["report_json"]
                    reports.append(raw if isinstance(raw, dict) else json.loads(raw))
                return reports
        except Exception as e:
            print(f"[!] Supabase get_all_scans error: {e}. Falling back to SQLite.")

    # SQLite
    try:
        conn = sqlite3.connect(SQLITE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT report_json FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [json.loads(r[0]) for r in rows]
    except Exception as e:
        print(f"[!] SQLite get_all_scans error: {e}")
        return []


def clear_all_scans() -> bool:
    """Clear all records from database."""
    success = True
    if _db_mode == "supabase" and _supabase_client:
        try:
            # Delete all records
            _supabase_client.table("scans").delete().neq("scan_id", "____none____").execute()
        except Exception as e:
            print(f"[!] Supabase clear error: {e}")
            success = False

    try:
        conn = sqlite3.connect(SQLITE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] SQLite clear error: {e}")
        success = False

    return success


def get_scan_stats() -> Dict[str, Any]:
    """Compute aggregate threat intelligence statistics."""
    scans = get_all_scans(limit=500)
    total = len(scans)
    if total == 0:
        return {
            "total_scans": 0,
            "safe_count": 0,
            "suspicious_count": 0,
            "critical_count": 0,
            "avg_score": 0.0,
            "high_risk_ratio": 0.0
        }

    safe = sum(1 for s in scans if s.get("verdict") in ["SAFE", "LOW_RISK"])
    suspicious = sum(1 for s in scans if s.get("verdict") == "SUSPICIOUS")
    critical = sum(1 for s in scans if s.get("verdict") in ["HIGH_RISK", "CRITICAL"])
    avg_score = sum(s.get("overall_score", 0.0) for s in scans) / total

    return {
        "total_scans": total,
        "safe_count": safe,
        "suspicious_count": suspicious,
        "critical_count": critical,
        "avg_score": round(avg_score, 1),
        "high_risk_ratio": round((critical / total) * 100, 1)
    }
