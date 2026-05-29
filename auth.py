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
import threading
import time
from typing import Any

import pyotp
from flask import g, redirect, request, session, url_for

import config
import database as db

log = logging.getLogger("soc.auth")

# OWASP 2023 minimum for PBKDF2-HMAC-SHA256. Existing lower-iteration hashes
# still verify (the count is encoded in each stored hash) and are transparently
# upgraded to this on the user's next successful login — see needs_rehash().
_PBKDF2_ITERATIONS = 600_000
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


def needs_rehash(stored: str) -> bool:
    """True if a stored PBKDF2 hash uses fewer iterations than the current
    target, so it should be transparently re-hashed on next successful login."""
    try:
        scheme, iters, _salt, _hash = stored.split("$", 3)
        return scheme == "pbkdf2" and int(iters) < _PBKDF2_ITERATIONS
    except (ValueError, TypeError, AttributeError):
        return False


# ---------- login brute-force throttle ------------------------------------
# In-process sliding-window limiter. The dashboard runs as a single waitress
# process, so module-level state shared across worker threads is sufficient (it
# resets on restart — an acceptable trade-off for a brute-force speed-bump).
# A locked-out attempt is refused BEFORE the password is hashed, which also
# blunts a hashing-CPU DoS via login spam. Tunable via env.
_LOGIN_WINDOW_S     = int(os.environ.get("SOC_LOGIN_WINDOW_S", "900"))    # 15 min
_LOGIN_MAX_PER_IP   = int(os.environ.get("SOC_LOGIN_MAX_PER_IP", "10"))
_LOGIN_MAX_PER_USER = int(os.environ.get("SOC_LOGIN_MAX_PER_USER", "5"))
_login_lock = threading.Lock()
_login_fails: dict[str, list[float]] = {}   # key -> failure timestamps (monotonic)


def _login_keys(ip: str | None, username: str) -> tuple[str, str]:
    return f"ip:{ip or '?'}", f"user:{(username or '').strip().lower()}"


def _login_prune(key: str, now: float) -> list[float]:
    kept = [t for t in _login_fails.get(key, []) if now - t < _LOGIN_WINDOW_S]
    if kept:
        _login_fails[key] = kept
    else:
        _login_fails.pop(key, None)
    return kept


def login_throttle_check(ip: str | None, username: str) -> float:
    """Seconds until this (ip, username) may try again, or 0.0 if not currently
    locked out. Read-only — records nothing."""
    now = time.monotonic()
    ip_key, user_key = _login_keys(ip, username)
    with _login_lock:
        ip_times = _login_prune(ip_key, now)
        user_times = _login_prune(user_key, now)
        retry = 0.0
        if len(ip_times) >= _LOGIN_MAX_PER_IP:
            retry = max(retry, _LOGIN_WINDOW_S - (now - ip_times[0]))
        if len(user_times) >= _LOGIN_MAX_PER_USER:
            retry = max(retry, _LOGIN_WINDOW_S - (now - user_times[0]))
        return max(0.0, retry)


def login_record_failure(ip: str | None, username: str) -> None:
    now = time.monotonic()
    with _login_lock:
        for key in _login_keys(ip, username):
            _login_fails.setdefault(key, []).append(now)


def login_record_success(ip: str | None, username: str) -> None:
    """Clear the failure counters for this IP + username (called on success)."""
    with _login_lock:
        for key in _login_keys(ip, username):
            _login_fails.pop(key, None)


# ---------- TOTP 2FA (optional, per-user) ---------------------------------

_TOTP_ISSUER = os.environ.get("SOC_TOTP_ISSUER", "HomeSOC")


def _clean_code(code: str | None) -> str:
    return (code or "").strip().replace(" ", "")


def _user_totp(user_id: int):
    """Return a pyotp.TOTP for the user's stored secret, or None."""
    row = db.get_user(user_id)
    if not row or not row["totp_secret"]:
        return None
    secret = config.decrypt(row["totp_secret"])
    return pyotp.TOTP(secret) if secret else None


def totp_begin_enroll(user: dict) -> dict:
    """Generate a fresh secret (stored disabled until confirmed) and return it
    plus an otpauth:// URI for the authenticator app."""
    secret = pyotp.random_base32()
    db.set_user_totp(user["id"], config.encrypt(secret), enabled=False)
    uri = pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name=_TOTP_ISSUER)
    return {"secret": secret, "otpauth_uri": uri}


def totp_confirm_enroll(user_id: int, code: str) -> bool:
    """Verify the first code against the pending secret; enable 2FA on success."""
    t = _user_totp(user_id)
    if not t or not t.verify(_clean_code(code), valid_window=1):
        return False
    db.set_user_totp(user_id, db.get_user(user_id)["totp_secret"], enabled=True)
    return True


def totp_verify(user_id: int, code: str) -> bool:
    """Verify a login code against an *enabled* secret (±1 step for clock skew)."""
    row = db.get_user(user_id)
    if not row or not row["totp_enabled"]:
        return False
    t = _user_totp(user_id)
    return bool(t and t.verify(_clean_code(code), valid_window=1))


def totp_disable(user_id: int, code: str) -> bool:
    """Disable 2FA — requires a currently-valid code (proves possession)."""
    if not totp_verify(user_id, code):
        return False
    db.set_user_totp(user_id, None, enabled=False)
    return True


# ---------- Flask integration --------------------------------------------

# Endpoints accessible without auth (login itself, the first-run setup page,
# static assets). The middleware allows these through.
PUBLIC_ENDPOINTS = {
    "auth.login_page", "auth.login_submit", "auth.login_2fa",
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
    # Home-consumer API (jacknet-home et al.): token-gated, NOT session-gated.
    # Default-OFF — disabled entirely until an operator sets a token.
    if request.path.startswith("/api/home/"):
        return _enforce_home_token()

    # First-run: no users yet → force the setup flow
    if db.count_users() == 0:
        if request.endpoint == "auth.setup_page":
            return None
        # API: respond 401 + JSON instead of redirect
        if request.path.startswith("/api/"):
            from flask import jsonify
            return jsonify({"success": False, "data": None,
                            "error": "setup required",
                            "redirect": "/setup"}), 401
        return redirect("/setup")

    user = current_user()
    if user:
        return None

    if request.path.startswith("/api/"):
        from flask import jsonify
        return jsonify({"success": False, "data": None,
                        "error": "authentication required",
                        "redirect": "/login"}), 401
    return redirect("/login?next=" + request.path)


# ---------- Home-consumer API token --------------------------------------

# The /api/home/* namespace serves a LAN consumer (e.g. jacknet-home wall
# display). It is gated by a shared bearer token rather than a session cookie.
# Security posture:
#   - DEFAULT-OFF: with no token set, the whole namespace returns 403. A fork
#     of HomeSOC is therefore NOT exposed until the operator opts in.
#   - Read-only by default: mutating endpoints (POST/PUT/PATCH/DELETE) require
#     a separate explicit flag, even with a valid token.
#   - Token stored Fernet-encrypted in settings; compared in constant time.
#   - Token accepted via `X-HomeSOC-Token` header or `Authorization: Bearer`.
#     For the SSE endpoint (EventSource can't set headers) a `?token=` query
#     param is also accepted — header is preferred everywhere else.

_HOME_TOKEN_KEY = "home_api_token"
_HOME_MUTATIONS_KEY = "home_api_allow_mutations"


def home_api_token_get() -> str | None:
    enc = db.setting_get(_HOME_TOKEN_KEY)
    if not enc:
        return None
    return config.decrypt(enc)


def home_api_token_set(token: str) -> None:
    db.setting_set(_HOME_TOKEN_KEY, config.encrypt(token))


def home_api_token_clear() -> None:
    db.setting_set(_HOME_TOKEN_KEY, None)


def home_api_generate_token() -> str:
    """Generate, store, and return a fresh random token (shown once)."""
    token = secrets.token_urlsafe(32)
    home_api_token_set(token)
    return token


def home_api_mutations_enabled() -> bool:
    return db.setting_get(_HOME_MUTATIONS_KEY) == "1"


def home_api_set_mutations(enabled: bool) -> None:
    db.setting_set(_HOME_MUTATIONS_KEY, "1" if enabled else "0")


def _present_home_token() -> str | None:
    """Extract the caller-supplied token from header or (SSE) query param."""
    hdr = request.headers.get("X-HomeSOC-Token")
    if hdr:
        return hdr
    authz = request.headers.get("Authorization", "")
    if authz.startswith("Bearer "):
        return authz[len("Bearer "):].strip()
    # EventSource cannot set headers; allow ?token= for the SSE stream only.
    if request.path == "/api/home/events":
        q = request.args.get("token")
        if q:
            return q
    return None


def _enforce_home_token():
    """Gate /api/home/*. Returns None to allow, or a JSON error response."""
    from flask import jsonify
    configured = home_api_token_get()
    if not configured:
        return jsonify({"success": False, "data": None,
                        "error": "home API disabled — set a token in Settings"}), 403

    presented = _present_home_token()
    if not presented or not hmac.compare_digest(presented, configured):
        return jsonify({"success": False, "data": None,
                        "error": "invalid or missing home API token"}), 401

    # Token valid. Gate mutations behind the explicit opt-in flag.
    if request.method not in ("GET", "HEAD", "OPTIONS") and not home_api_mutations_enabled():
        return jsonify({"success": False, "data": None,
                        "error": "home API mutations are disabled"}), 403
    return None


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
    ip = request.remote_addr

    # Brute-force throttle: refuse (without hashing) once too many recent
    # failures are seen for this IP or username.
    locked_for = login_throttle_check(ip, username)
    if locked_for > 0:
        mins = int(locked_for // 60) + 1
        return render_template(
            "login.html", theme=config.DEFAULT_THEME,
            error=f"Too many failed attempts. Try again in ~{mins} min.",
            next=next_path), 429

    row = db.get_user_by_username(username)
    if row and not row["disabled"] and verify_password(password, row["password_hash"]):
        login_record_success(ip, username)
        # Transparently upgrade legacy / low-iteration hashes (no forced reset).
        if needs_rehash(row["password_hash"]):
            try:
                db.update_user_password(row["id"], hash_password(password))
                audit("user.password_rehash", "user", row["id"],
                      {"iterations": _PBKDF2_ITERATIONS})
            except Exception:  # noqa: BLE001
                log.warning("password rehash failed for user %s", row["id"])
        # Second factor: hold the login until a valid TOTP code is supplied.
        if row["totp_enabled"]:
            session.pop("user_id", None)
            session["pending_2fa_uid"] = row["id"]
            return render_template("login.html", theme=config.DEFAULT_THEME,
                                   totp=True, next=next_path)
        session["user_id"] = row["id"]
        db.update_user_login(row["id"])
        audit("user.login", "user", row["id"])
        # Prevent open-redirect: only allow same-origin paths
        if not next_path.startswith("/") or next_path.startswith("//"):
            next_path = "/"
        return redirect(next_path)

    login_record_failure(ip, username)
    audit("user.login_failed", "user", row["id"] if row else None,
          {"username": username})
    return render_template(
        "login.html", theme=config.DEFAULT_THEME,
        error="Invalid username or password.", next=next_path), 401


@auth_bp.route("/login/2fa", methods=["POST"])
def login_2fa():
    """Second step of login for 2FA-enabled users: verify the TOTP code held
    against the pending user id stored in the session by login_submit."""
    uid = session.get("pending_2fa_uid")
    next_path = request.form.get("next") or "/"
    if not uid:
        return redirect("/login")
    ip = request.remote_addr
    key = f"2fa:{uid}"
    if login_throttle_check(ip, key) > 0:
        return render_template("login.html", theme=config.DEFAULT_THEME, totp=True,
                               error="Too many attempts. Try again shortly.",
                               next=next_path), 429
    if totp_verify(uid, request.form.get("code") or ""):
        login_record_success(ip, key)
        session.pop("pending_2fa_uid", None)
        session["user_id"] = uid
        db.update_user_login(uid)
        audit("user.login", "user", uid, {"via": "totp"})
        if not next_path.startswith("/") or next_path.startswith("//"):
            next_path = "/"
        return redirect(next_path)
    login_record_failure(ip, key)
    audit("user.login_2fa_failed", "user", uid)
    return render_template("login.html", theme=config.DEFAULT_THEME, totp=True,
                           error="Invalid authentication code.", next=next_path), 401


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
