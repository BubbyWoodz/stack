#!/usr/bin/env python3
"""Stack - self-hosted supplement tracker (server side).

The server is deliberately dumb: it stores ONE opaque encrypted vault blob
per install and never sees plaintext. All encryption/decryption happens in
the browser with WebCrypto (PBKDF2 -> AES-256-GCM), keyed by the user's
12-word recovery code. The server operator cannot read user data.

Endpoints:
  GET  /                -> web app
  GET  /healthz          -> liveness
  GET  /api/vault       -> {"version": n, "updated_at": iso, "iv": b64, "ciphertext": b64}
                          or 404 {"exists": false} on first run
  PUT  /api/vault       -> {"iv": b64, "ciphertext": b64, "base_version": n}
                          optimistic concurrency: 409 if base_version != current
"""
import base64
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from flask import Flask, jsonify, request, send_from_directory

DB_PATH = os.environ.get("STACK_DB", "/data/stack.db")
PORT = int(os.environ.get("PORT", "8096"))
MAX_BLOB_BYTES = 10 * 1024 * 1024  # 10 MB sanity cap on the vault blob

app = Flask(__name__, static_folder="static", static_url_path="")
_lock = threading.Lock()


def get_db():
    db = sqlite3.connect(DB_PATH, timeout=30)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    parent = os.path.dirname(DB_PATH)
    if parent:
        os.makedirs(parent, exist_ok=True)
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            version INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            iv TEXT NOT NULL,
            ciphertext TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


def _b64_ok(s):
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})


@app.route("/api/vault", methods=["GET"])
def get_vault():
    db = get_db()
    row = db.execute("SELECT version, updated_at, iv, ciphertext FROM vault WHERE id = 1").fetchone()
    db.close()
    if not row:
        return jsonify({"exists": False}), 404
    return jsonify(
        {
            "exists": True,
            "version": row["version"],
            "updated_at": row["updated_at"],
            "iv": row["iv"],
            "ciphertext": row["ciphertext"],
        }
    )


@app.route("/api/vault", methods=["PUT"])
def put_vault():
    data = request.get_json(force=True, silent=True) or {}
    iv = data.get("iv")
    ciphertext = data.get("ciphertext")
    base_version = data.get("base_version", 0)
    if not isinstance(iv, str) or not isinstance(ciphertext, str):
        return jsonify({"error": "iv and ciphertext are required"}), 400
    if not _b64_ok(iv) or not _b64_ok(ciphertext):
        return jsonify({"error": "iv/ciphertext must be base64"}), 400
    if len(ciphertext) > MAX_BLOB_BYTES:
        return jsonify({"error": "vault blob too large"}), 413
    try:
        base_version = int(base_version)
    except (TypeError, ValueError):
        return jsonify({"error": "base_version must be an integer"}), 400

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _lock:
        db = get_db()
        try:
            row = db.execute("SELECT version FROM vault WHERE id = 1").fetchone()
            current = row["version"] if row else 0
            if base_version != current:
                return (
                    jsonify(
                        {
                            "error": "version conflict",
                            "server_version": current,
                        }
                    ),
                    409,
                )
            new_version = current + 1
            db.execute(
                """INSERT INTO vault (id, version, updated_at, iv, ciphertext)
                   VALUES (1, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                     version = excluded.version,
                     updated_at = excluded.updated_at,
                     iv = excluded.iv,
                     ciphertext = excluded.ciphertext""",
                (new_version, now, iv, ciphertext),
            )
            db.commit()
        finally:
            db.close()
    return jsonify({"ok": True, "version": new_version, "updated_at": now})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=PORT)
