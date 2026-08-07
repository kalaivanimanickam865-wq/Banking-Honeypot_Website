"""All routes for the fake banking site: public pages, auth, and the
session-gated dummy customer area (dashboard/transactions/profile).
"""
import uuid

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .honeypot_logger import log_login_attempt
from .models import User

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
