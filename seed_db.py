"""Seed a handful of demo customer accounts so the login form has
real credentials to validate against. Run once: python seed_db.py

Without seeded users, EVERY login attempt (including legitimate
demo logins) would fail, which defeats the point of having a
success/failed distinction for the AI to learn from.

Usernames/passwords here are for local demo/grading use only —
never reuse real credentials in this file.
"""
import argparse

from werkzeug.security import generate_password_hash

from app import create_app
from app.extensions import db
from app.models import User

DEFAULT_DEMO_USERS = [
    {"username": "admin", "password": "Adm!n#2026Secure", "full_name": "Bank Admin", "account_number": "IN0001234567"},
    {"username": "rajesh.kumar", "password": "Raj@Kumar2026!", "full_name": "Rajesh Kumar", "account_number": "IN0009876543"},
    {"username": "priya.sharma", "password": "PriyaS#4521!", "full_name": "Priya Sharma", "account_number": "IN0005647382"},
]


def seed(reset: bool = False):
    app = create_app()
    with app.app_context():
        if reset:
            User.query.delete()
            db.session.commit()

        db.create_all()
        created = 0
        for u in DEFAULT_DEMO_USERS:
            if not User.query.filter_by(username=u["username"]).first():
                db.session.add(User(
                    username=u["username"],
                    password_hash=generate_password_hash(u["password"]),
                    full_name=u["full_name"],
                    account_number=u["account_number"],
                ))
                created += 1
        db.session.commit()
        print(f"Seeded {created} new demo user(s). Total demo accounts defined: {len(DEFAULT_DEMO_USERS)}.")
        print("Credentials (for your own testing only):")
        for u in DEFAULT_DEMO_USERS:
            print(f"  {u['username']} / {u['password']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed demo bank users into the database.")
    parser.add_argument("--reset", action="store_true", help="Delete existing users before seeding.")
    args = parser.parse_args()
    seed(reset=args.reset)
