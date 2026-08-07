"""All routes for the fake banking site: public pages, auth, and the
session-gated dummy customer area (dashboard/transactions/profile).
"""
import uuid

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .extensions import db
from .honeypot_logger import get_recent_attempt_count, get_top_attacking_ips, log_login_attempt
from .models import LoginAttempt, User

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # One session_id per browser session, so all attempts from
        # the same attacker script land in the same "session_id"
        # bucket for the AI's feature engineering.
        if "hp_session_id" not in session:
            session["hp_session_id"] = str(uuid.uuid4())

        user = User.query.filter_by(username=username).first()
        is_valid = bool(user) and check_password_hash(user.password_hash, password)
        status = "success" if is_valid else "failed"

        should_log = status == "failed" or current_app.config.get("LOG_SUCCESSFUL_LOGINS", True)
        if should_log:
            log_login_attempt(username, password, status, session["hp_session_id"])

        if is_valid:
            session["user_id"] = user.id
            session["username"] = user.username
            return redirect(url_for("main.dashboard"))

        # Deliberately generic error — an attacker probing the form
        # shouldn't be able to tell valid usernames from invalid ones
        flash("Invalid username or password.", "error")
        return render_template("login.html"), 401

    return render_template("login.html")


@bp.route("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")


@bp.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("main.login"))
    user = User.query.get(session["user_id"])
    return render_template("dashboard.html", user=user)


@bp.route("/transactions")
def transactions():
    if "user_id" not in session:
        return redirect(url_for("main.login"))
    # Dummy data — this is a honeypot, there is no real ledger.
    # Replace with a real Transaction model only if the project
    # scope grows beyond "convincing decoy UI".
    dummy_transactions = [
        {"date": "2026-07-28", "desc": "UPI - Grocery Store", "amount": -1245.00},
        {"date": "2026-07-27", "desc": "Salary Credit", "amount": 65000.00},
        {"date": "2026-07-25", "desc": "Electricity Bill Payment", "amount": -2100.50},
        {"date": "2026-07-22", "desc": "ATM Withdrawal", "amount": -5000.00},
        {"date": "2026-07-18", "desc": "Mobile Recharge", "amount": -499.00},
    ]
    return render_template("transactions.html", transactions=dummy_transactions)


@bp.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("main.login"))
    user = User.query.get(session["user_id"])
    return render_template("profile.html", user=user)


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.index"))


# ---------------------------------------------------------------------------
# Read-only JSON API — the handoff surface for Members 3–6.
#
# Member 3 doesn't need these (it just POSTs to /login directly), but
# Members 4/5/6 all want to pull login_attempts data without writing
# raw SQLite queries against a DB file path they'd have to guess.
# No auth on these routes: this is a local research project, not a
# system with real users to protect.
# ---------------------------------------------------------------------------

@bp.route("/api/login-attempts")
def api_login_attempts():
    """Paginated raw log rows, newest first.

    Query params:
      limit   int, default 100, max 1000
      offset  int, default 0
      status  optional filter: "success" or "failed"
      ip      optional filter: exact IP match
    """
    limit = min(request.args.get("limit", 100, type=int), 1000)
    offset = request.args.get("offset", 0, type=int)
    status = request.args.get("status")
    ip = request.args.get("ip")

    query = LoginAttempt.query
    if status in ("success", "failed"):
        query = query.filter_by(login_status=status)
    if ip:
        query = query.filter_by(ip_address=ip)

    total = query.count()
    rows = (
        query.order_by(LoginAttempt.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "attempts": [
            {
                "id": r.id,
                "username_attempted": r.username_attempted,
                "password_attempted": r.password_attempted,
                "ip_address": r.ip_address,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "browser": r.browser,
                "user_agent": r.user_agent,
                "session_id": r.session_id,
                "login_status": r.login_status,
                "country": r.country,
            }
            for r in rows
        ],
    })


@bp.route("/api/stats")
def api_stats():
    """Quick-glance counters for a live dashboard (Member 6) without
    it needing to compute aggregates itself on every refresh."""
    total = LoginAttempt.query.count()
    failed = LoginAttempt.query.filter_by(login_status="failed").count()
    success = LoginAttempt.query.filter_by(login_status="success").count()
    unique_ips = db.session.query(LoginAttempt.ip_address).distinct().count()
    top_ips = get_top_attacking_ips(limit=10)

    return jsonify({
        "total_attempts": total,
        "failed_attempts": failed,
        "successful_attempts": success,
        "unique_ips": unique_ips,
        "top_attacking_ips": [
            {"ip_address": ip, "failed_attempts": count} for ip, count in top_ips
        ],
    })


@bp.route("/api/ip-check/<ip_address>")
def api_ip_check(ip_address):
    """How active has this specific IP been recently — the kind of
    lookup Member 5's threat report or a live dashboard would fire
    on click-through from a table row."""
    recent_5min = get_recent_attempt_count(ip_address, minutes=5)
    recent_1hr = get_recent_attempt_count(ip_address, minutes=60)
    total = LoginAttempt.query.filter_by(ip_address=ip_address).count()

    return jsonify({
        "ip_address": ip_address,
        "total_attempts": total,
        "attempts_last_5min": recent_5min,
        "attempts_last_1hr": recent_1hr,
    })
