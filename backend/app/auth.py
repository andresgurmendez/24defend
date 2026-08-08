import hashlib
import hmac
import secrets
import time

from fastapi import Header, HTTPException, Request

from app.config import settings

DASHBOARD_SESSION_COOKIE = "defend_dashboard_session"
DASHBOARD_SESSION_TTL_SECONDS = 12 * 60 * 60  # 12h


async def require_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """Gates /admin/* — the full-privilege, machine-only key. The dashboard
    never sends this (see require_dashboard_session): a leaked dashboard
    session cannot be used to reach /admin/*.
    """
    if x_api_key is None or not secrets.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


def _sign_session(expiry: int) -> str:
    mac = hmac.new(settings.session_secret.encode(), str(expiry).encode(), hashlib.sha256).hexdigest()
    return f"{expiry}.{mac}"


def create_dashboard_session() -> str:
    expiry = int(time.time()) + DASHBOARD_SESSION_TTL_SECONDS
    return _sign_session(expiry)


def _dashboard_session_valid(token: str) -> bool:
    expiry_str, sep, _ = token.partition(".")
    if not sep or not expiry_str.isdigit():
        return False
    expiry = int(expiry_str)
    if time.time() > expiry:
        return False
    return secrets.compare_digest(token, _sign_session(expiry))


async def require_dashboard_session(request: Request) -> None:
    """Gates dashboard read endpoints (GET /telemetry/stats). A short-lived,
    HttpOnly cookie issued by POST /telemetry/login against a dedicated
    read-only dashboard key (settings.dashboard_api_key) — deliberately NOT
    the admin api_key. JS can't read an HttpOnly cookie, so a dashboard XSS
    can't exfiltrate it, and even if it could, the cookie grants no
    /admin/* access (see PR #14 review findings #1/#2).
    """
    token = request.cookies.get(DASHBOARD_SESSION_COOKIE)
    if not token or not _dashboard_session_valid(token):
        raise HTTPException(status_code=401, detail="Not authenticated")
