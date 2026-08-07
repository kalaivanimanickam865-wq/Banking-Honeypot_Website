# Architecture — Fake Banking Website + Auth + Honeypot Logging + DB
**Owner:** Member 1 (Sathya) — this module covers the Member 1 role *plus* the Member 2 backend/auth/DB role, since you're building both.
**Research question this serves:** Can an AI-powered banking honeypot detect and analyze brute-force attacks and generate cyber threat intelligence?

## 1. Scope of this module

| In scope (you build) | Out of scope (other members) |
|---|---|
| Banking website UI (home, login, forgot password, dashboard, transactions, profile) | Attack simulator scripts (Member 3) |
| Flask backend + REST-style routes | ML training / detection (Member 4) |
| Authentication logic | Threat intel analysis, GeoIP (Member 5) |
| Honeypot logger (writes every login attempt to DB) | Streamlit admin dashboard (Member 6) |
| SQLite database + schema | |

Your deliverable is the **origin of the pipeline**: every other member's module reads from the `login_attempts` table you create, so schema stability matters more than feature completeness.

## 2. System diagram

```
                     Browser (Attacker or Normal User)
                                  │
                                  ▼
                    Fake Banking Website (Flask + Jinja2)
                    ┌─────────────────────────────────┐
                    │  /            → index            │
                    │  /login       → GET + POST        │
                    │  /forgot-password → dummy         │
                    │  /dashboard   → session-gated      │
                    │  /transactions→ session-gated      │
                    │  /profile     → session-gated      │
                    │  /logout      → clears session     │
                    └─────────────────┬─────────────────┘
                                       │
                     POST /login      ▼
                    ┌─────────────────────────────────┐
                    │  Auth check (User table)          │
                    │  Honeypot Logger (ALWAYS runs)     │
                    └─────────────────┬─────────────────┘
                                       ▼
                            SQLite: honeypot.db
                    ┌─────────────────────────────────┐
                    │  users            (real accounts) │
                    │  login_attempts   (every attempt) │
                    └─────────────────────────────────┘
                                       │
                        read by Member 3/4/5/6 modules
```

## 3. Database schema

**`users`** — seeded demo accounts the login form validates against. Brute-force only "succeeds" if it guesses one of these.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| username | VARCHAR(80) UNIQUE | |
| password_hash | VARCHAR(255) | werkzeug `generate_password_hash`, never plaintext |
| full_name | VARCHAR(120) | |
| account_number | VARCHAR(20) UNIQUE | dummy display value |
| balance | FLOAT | dummy display value |
| created_at | DATETIME | |

**`login_attempts`** — the honeypot log. This is the table Member 3 generates traffic into, Member 4 trains the model on, and Member 5 enriches with `country`.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| username_attempted | VARCHAR(120) | whatever the client sent, not validated |
| password_attempted | VARCHAR(255) | **stored in plaintext, intentionally.** This is a research honeypot, not a production bank — the raw guessed password is a required feature for password-pattern analysis (Member 5) and is never a real user's actual password since attackers are guessing. Do not reuse this pattern in a real system. |
| ip_address | VARCHAR(45) | reads `X-Forwarded-For` if behind a proxy, else `remote_addr` |
| timestamp | DATETIME, indexed | |
| browser | VARCHAR(100) | parsed from user-agent |
| user_agent | VARCHAR(255) | raw string |
| session_id | VARCHAR(64) | groups attempts from one browser session |
| login_status | VARCHAR(20) | `success` \| `failed` |
| country | VARCHAR(80), nullable | left NULL — Member 5 fills this via GeoIP2 in a later pass, does not block your module |

## 4. Request flow for one login POST

```
1. Client submits username + password to /login
2. Server assigns a session_id if one doesn't exist yet
3. Server looks up username in `users`, checks password hash
4. Server calls log_login_attempt() UNCONDITIONALLY — this happens
   before the success/fail branch, so failed brute-force attempts
   are captured with the same fidelity as legitimate logins
5. If valid → session cookie set → redirect to /dashboard
   If invalid → 401 + flash error, attacker sees a normal-looking
   "invalid credentials" page (no hint that they're in a honeypot)
```

## 5. Tech stack

- Flask 3 (application factory pattern, `app/__init__.py`)
- Flask-SQLAlchemy (ORM, swappable to Postgres later without route changes)
- SQLite (`instance/honeypot.db`, gitignored — never commit a DB file)
- Jinja2 + Bootstrap 5 (CDN) for the banking UI
- Werkzeug password hashing for the `users` table only (never for `login_attempts`)

## 6. Folder structure

```
banking-honeypot/
├── app/
│   ├── __init__.py        # app factory
│   ├── config.py          # env-driven config
│   ├── extensions.py      # db = SQLAlchemy()
│   ├── models.py          # User, LoginAttempt
│   ├── honeypot_logger.py # log_login_attempt()
│   └── routes.py          # all Flask routes
├── templates/              # Jinja2 HTML
├── static/
│   ├── css/style.css
│   └── js/main.js
├── instance/                # gitignored — SQLite DB lives here at runtime
├── seed_db.py               # creates demo users
├── run.py                   # entry point
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── ARCHITECTURE.md
```

## 7. Security notes (read before demoing)

- This app is **deliberately un-hardened** against brute force (no rate limiting, no CAPTCHA, no account lockout) — that's the point, the honeypot needs to observe the full attack, not block it at attempt #3.
- Never deploy this to a public host with real user data. Use fake demo accounts only (see `seed_db.py`).
- `SECRET_KEY` must come from an environment variable in any shared/deployed environment — `.env` is gitignored for this reason.

## 8. Handoff points for other members

| Member | Reads from you |
|---|---|
| 3 (Attack Simulator) | POSTs to `/login` — no API key needed, it's a public form |
| 4 (AI Detection) | Reads `login_attempts` table (via SQLAlchemy or direct SQLite query) |
| 5 (Threat Intel) | Reads `login_attempts`, writes back into `country` column |
| 6 (Dashboard) | Reads both tables read-only for live stats |

Keep the `login_attempts` schema stable once Member 3 starts generating traffic — changing column names later breaks everyone downstream.
