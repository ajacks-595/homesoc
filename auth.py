"""Authentication: PBKDF2-hashed passwords, signed session cookies.

Design:
- First-run UX: when `users` table is empty, all routes redirect to /setup
  so the operator creates the first admin account.
- After at least one user exists, unauthenticated requests redirect to /login.
- Sessions are Flask's `session` object (server-side via secret_key signing).
- Audit log entries are stamped with the current user via the request context.

Roles are flat (single role per user) for now; only "admin" is recognised but
all logged-in users are treated equally. The schema is ready for richer roles
without further migration.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import logging
import os
import secrets
from typing import Any

from flask import g, redirect, request, session, url_for

import config
import database as db

log = logging.getLogger("soc.auth")

_PBKDF2_ITERATIONS = 200_000
_PBKDF2_ALGO = "sha256"


def _gen_salt() -> bytes:
    return secrets.token_bytes(16)


def hash_password(password: str, salt: bytes | None = None) -> str:
    """PBKDF2-SHA256 hash. Stored format: `pbkdf2$<iters>$<salt_b64>$<hash_b64>`."""
    salt = salt or _gen_salt()
    h = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode(), salt, _PBKDF2_ITERATIONS)
    return (f"pbkdf2${_PBKDF2_ITERATIONS}$"
            f"{base64.b64encode(salt).decode()}$"
            f"{base64.b64encode(h).decode()}")


def verify_password(password: str, stored: str) -> bool:
    """Constant-time compare. Returns False on any malformed input."""
    try:
        scheme, iters, salt_b64, hash_b64 = stored.split("$", 3)
        if scheme != "pbkdf2":
            return False
        iters_n = int(iters)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        h = hashlib.pbkdf2_hmac(_PBKDF2_ALGO, password.encode(), salt, iters_n)
        return hmac.compare_digest(h, expected)
    except (ValueError, TypeError):
        return False


# ---------- Flask integration --------------------------------------------

# Endpoints accessible without auth (login itself, the first-run setup page,
# static assets). The middleware allows these through.
PUBLIC_ENDPOINTS = {
    "auth.login_page", "auth.login_submit",
    "auth.setup_page", "auth.setup_submit",
    "auth.logout",
    "static",
}


def current_user() -> dict | None:
    """Return the logged-in user dict, or None. Cached per-request on g."""
    cached = getattr(g, "_current_user", None)
    if cached is not None:
        return cached or None
    user_id = session.get("user_id")
    if not user_id:
        g._current_user = False
        return None
    row = db.get_user(user_id)
    if not row or row["disabled"]:
        session.pop("user_id", None)
        g._current_user = False
        return None
    user = dict(row)
    g._current_user = user
    return user


def login_required_globally():
    """Middleware: redirect anything unauthenticated to /login or /setup."""
    # Allow static assets and explicit public endpoints
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None
    if request.endpoint and request.endpoint.startswith("static"):
        return None
    # Read-only home-dashboard endpoints — LAN-only consumers (jacknet-home).
    if request.path.startswith("/api/home/"):
        return None

    # First-run: no users yet → force the setup flow
    if db.count_users() == 0:
        if request.endpoint == "auth.setup_page":
            return None
        # API: respond 401 + JSON instead of redirect
        if request.path.startswith("/api/"):
            from flask import jsonify
            return jsonify({"success": False, "error": "setup required",
                            "redirect": "/setup"}), 401
        return redirect("/setup")

    user = current_user()
    if user:
        return None

    if request.path.startswith("/api/"):
        from flask import jsonify
        return jsonify({"success": False, "error": "authentication required",
                        "redirect": "/login"}), 401
    return redirect("/login?next=" + request.path)


def audit(action: str, target_type: str | None = None,
          target_id: str | int | None = None, details: dict | None = None) -> None:
    """Add an audit log entry stamped with the current user + request IP."""
    user = current_user() or {}
    import json as _json
    db.audit_add(
        user_id=user.get("id"),
        username=user.get("username"),
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        details=_json.dumps(details) if details else None,
        ip_address=request.remote_addr if request else None,
    )


# ---------- blueprint -----------------------------------------------------

from flask import Blueprint, render_template, request as _req
auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/setup", methods=["GET"])
def setup_page():
    # If users already exist, redirect to login
    if db.count_users() > 0:
        return redirect("/login")
    return render_template("setup.html", theme=config.DEFAULT_THEME)


@auth_bp.route("/setup", methods=["POST"])
def setup_submit():
    if db.count_users() > 0:
        return redirect("/login")
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not username or len(password) < 8:
        return render_template(
            "setup.html", theme=config.DEFAULT_THEME,
            error="Username required and password must be at least 8 characters."), 400
    uid = db.insert_user(username, hash_password(password), role="admin")
    session["user_id"] = uid
    db.update_user_login(uid)
    audit("user.setup", "user", uid, {"username": username})
    return redirect("/")


@auth_bp.route("/login", methods=["GET"])
def login_page():
    next_path = request.args.get("next", "/")
    return render_template("login.html", theme=config.DEFAULT_THEME, next=next_path)


@auth_bp.route("/login", methods=["POST"])
def login_submit():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    next_path = request.form.get("next") or "/"
    row = db.get_user_by_username(username)
    if row and not row["disabled"] and verify_password(password, row["password_hash"]):
        session["user_id"] = row["id"]
        db.update_user_login(row["id"])
        audit("user.login", "user", row["id"])
        # Prevent open-redirect: only allow same-origin paths
        if not next_path.startswith("/") or next_path.startswith("//"):
            next_path = "/"
        return redirect(next_path)
    return render_template(
        "login.html", theme=config.DEFAULT_THEME,
        error="Invalid username or password.", next=next_path), 401


@auth_bp.route("/logout")
def logout():
    user = current_user()
    if user:
        audit("user.logout", "user", user["id"])
    session.pop("user_id", None)
    return redirect("/login")


# ---------- secret key bootstrap ------------------------------------------

def get_or_create_secret_key() -> bytes:
    """Persist Flask's session secret in the settings table so cookies survive
    restarts. Generated once on first run."""
    enc = db.setting_get("flask_secret_key")
    if enc:
        sk = config.decrypt(enc)
        if sk:
            return base64.b64decode(sk)
    raw = secrets.token_bytes(32)
    db.setting_set("flask_secret_key", config.encrypt(base64.b64encode(raw).decode()))
    return raw
