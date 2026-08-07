"""Honeypot logging — the core function this whole module exists for.

log_login_attempt() is called on EVERY POST to /login, before the
success/fail branch is decided. That's what makes this a honeypot
rather than a normal login form: a real bank blocks you after 3 bad
attempts, this one just watches and records, so Member 3's simulator
can generate a full brute-force dataset for Member 4's model.
"""
from datetime import datetime, timedelta

from flask import current_app, request

from .extensions import db
from .models import LoginAttempt


def get_client_ip():
    """Prefer X-Forwarded-For (set by a reverse proxy / hosting
    platform in front of Flask) over remote_addr, which would
    otherwise just show the proxy's IP for every request."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def parse_browser(user_agent_string: str) -> str:
    """Cheap browser-family parse — good enough for the 'Browser'
    column Member 5's threat report groups by. Not meant to replace
    a real user-agent parsing library if more precision is needed
    later."""
    ua = (user_agent_string or "").lower()
    if "edg" in ua:
        return "Edge"
    if "chrome" in ua and "chromium" not in ua:
        return "Chrome"
    if "firefox" in ua:
        return "Firefox"
    if "safari" in ua and "chrome" not in ua:
        return "Safari"
    if "python-requests" in ua or "curl" in ua:
        return "Script/Bot"
    return "Other"


def log_login_attempt(username: str, password: str, status: str, session_id: str) -> LoginAttempt:
    """Persist one login attempt. Returns the saved row.

    Args:
        username: raw value submitted in the form, not validated
        password: raw value submitted in the form (see models.py for
            why this is stored in plaintext for this table only)
        status: "success" or "failed"
        session_id: groups attempts from the same browser session,
            so Member 4's features can compute attempts-per-session
    """
    max_len = current_app.config.get("MAX_LOGGED_PASSWORD_LENGTH", 255)

    attempt = LoginAttempt(
        username_attempted=(username or "")[:120],
        password_attempted=(password or "")[:max_len],
        ip_address=get_client_ip(),
        timestamp=datetime.utcnow(),
        browser=parse_browser(request.user_agent.string),
        user_agent=(request.user_agent.string or "")[:255],
        session_id=session_id,
        login_status=status,
    )
    db.session.add(attempt)
    db.session.commit()
    return attempt


def get_recent_attempt_count(ip_address: str, minutes: int = 5) -> int:
    """How many login attempts this IP has made in the last N minutes.

    Not used to block anything — this honeypot never locks attackers
    out — but Member 5's threat report and Member 6's live dashboard
    both want a quick "is this IP currently hammering the form"
    number, and Member 4's feature engineering wants it as a raw
    input feature too. Centralizing it here means everyone queries
    it the same way instead of re-deriving it from raw timestamps.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=minutes)
    return LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp >= cutoff,
    ).count()


def get_top_attacking_ips(limit: int = 10, status: str = "failed"):
    """IPs ranked by failed-attempt volume, most active first.

    Returns a list of (ip_address, attempt_count) tuples. This is a
    convenience wrapper — Member 5's full threat-intel pass does the
    deeper GeoIP/country enrichment, but this gives Member 6's
    dashboard something to render on day one without waiting on
    that module.
    """
    from sqlalchemy import func

    query = (
        db.session.query(
            LoginAttempt.ip_address,
            func.count(LoginAttempt.id).label("attempts"),
        )
        .filter(LoginAttempt.login_status == status)
        .group_by(LoginAttempt.ip_address)
        .order_by(func.count(LoginAttempt.id).desc())
        .limit(limit)
    )
    return query.all()
