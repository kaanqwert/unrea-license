from flask import Flask, request, jsonify
import hashlib
import secrets
import time
import sqlite3
import os

app = Flask(__name__)

# ============================================================
# AYARLAR - BURAYI DEĞİŞTİR!
# ============================================================
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "DEFAULT_DEGISTIR")  # ← Bunu değiştir!
DB_FILE = "licenses.db"
# ============================================================


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key_hash TEXT PRIMARY KEY,
            hwid TEXT,
            expiry INTEGER,
            active INTEGER DEFAULT 1,
            created_at INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


@app.route("/")
def home():
    return "Unrea License Server is running!"


@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json()
    if not data:
        return jsonify({"valid": False, "error": "no_data"}), 400

    key = data.get("key", "").strip()
    hwid = data.get("hwid", "").strip()

    if not key or not hwid:
        return jsonify({"valid": False, "error": "missing_fields"}), 400

    key_h = hash_key(key)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT hwid, expiry, active FROM licenses WHERE key_hash=?", (key_h,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"valid": False, "error": "invalid_key"}), 403

    db_hwid, expiry, active = row

    if not active:
        conn.close()
        return jsonify({"valid": False, "error": "revoked"}), 403

    if expiry > 0 and time.time() > expiry:
        conn.close()
        return jsonify({"valid": False, "error": "expired"}), 403

    if db_hwid is None:
        c.execute("UPDATE licenses SET hwid=? WHERE key_hash=?", (hwid, key_h))
        conn.commit()
    elif db_hwid != hwid:
        conn.close()
        return jsonify({"valid": False, "error": "hwid_mismatch"}), 403

    conn.close()
    return jsonify({"valid": True, "expiry": expiry})


@app.route("/admin/create", methods=["POST"])
def admin_create():
    data = request.get_json()
    if not data or data.get("password") != ADMIN_PASSWORD:
        return jsonify({"error": "unauthorized"}), 401

    key = secrets.token_urlsafe(24)
    key_h = hash_key(key)

    days = int(data.get("days", 30))
    expiry = int(time.time()) + (days * 86400) if days > 0 else 0

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO licenses (key_hash, hwid, expiry, active, created_at) VALUES (?, NULL, ?, 1, ?)",
              (key_h, expiry, int(time.time())))
    conn.commit()
    conn.close()

    return jsonify({"key": key, "days": days})


@app.route("/admin/list", methods=["POST"])
def admin_list():
    data = request.get_json()
    if not data or data.get("password") != ADMIN_PASSWORD:
        return jsonify({"error": "unauthorized"}), 401

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT key_hash, hwid, expiry, active FROM licenses")
    rows = c.fetchall()
    conn.close()

    result = []
    for r in rows:
        result.append({
            "key_hash": r[0][:16] + "...",
            "hwid": r[1] or "not_bound",
            "expiry": r[2],
            "active": bool(r[3])
        })
    return jsonify({"licenses": result, "count": len(result)})


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    data = request.get_json()
    if not data or data.get("password") != ADMIN_PASSWORD:
        return jsonify({"error": "unauthorized"}), 401

    key = data.get("key", "")
    key_h = hash_key(key)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE licenses SET active=0 WHERE key_hash=?", (key_h,))
    affected = c.rowcount
    conn.commit()
    conn.close()

    if affected > 0:
        return jsonify({"success": True})
    return jsonify({"error": "not_found"}), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
