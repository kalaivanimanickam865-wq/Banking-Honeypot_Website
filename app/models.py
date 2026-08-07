from datetime import datetime

from .extensions import db


class User(db.Model):
    """Real (demo) bank customer accounts. This is what the login
    form validates against — brute force only "succeeds" when a
    guess matches one of these. Seeded by seed_db.py."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120))
    account_number = db.Column(db.String(20), unique=True)
    balance = db.Column(db.Float, default=125000.00)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username}>"


class LoginAttempt(db.Model):
    """The honeypot log. Every POST to /login writes a row here,
    success or fail, before the response is returned to the client.

    This table is the handoff point to the rest of the team:
    Member 3 generates traffic into it, Member 4 trains the
    detection model on it, Member 5 enriches it via `country`,
    Member 6 reads it for the live dashboard.

    password_attempted is stored in PLAINTEXT intentionally — see
    ARCHITECTURE.md section 3 for why. This is a research honeypot,
    never a production auth table.
    """

    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    username_attempted = db.Column(db.String(120), index=True)
    password_attempted = db.Column(db.String(255))
    ip_address = db.Column(db.String(45), index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    browser = db.Column(db.String(100))
    user_agent = db.Column(db.String(255))
    session_id = db.Column(db.String(64), index=True)
    login_status = db.Column(db.String(20))  # "success" | "failed"

    # Nullable, filled in later by Member 5's Threat Intelligence
    # pass (GeoIP2 lookup on ip_address). Not required for this
    # module to function — left here so the schema doesn't need to
    # change when that module lands.
    country = db.Column(db.String(80), nullable=True)

    def __repr__(self):
        return f"<LoginAttempt {self.username_attempted} {self.login_status} @ {self.timestamp}>"
