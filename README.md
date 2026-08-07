# Banking Honeypot — Member 1 Module (Frontend + Auth + Honeypot Logger + DB)

Part of: **AI-Powered Banking Honeypot for Brute-Force Detection & Threat Intelligence**

This module is the origin of the whole pipeline — a realistic fake banking website whose login form authenticates against a real (demo) user table while logging **every** attempt, successful or not, into a `login_attempts` table for the rest of the team to build on. See `ARCHITECTURE.md` for the full design, schema, and handoff points.

## Setup

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy the env template and adjust if needed
cp .env.example .env

# 4. Seed demo customer accounts
python seed_db.py

# 5. Run the app
python run.py
```

Visit `http://127.0.0.1:5000`. Demo login credentials are printed by `seed_db.py` (also listed in `ARCHITECTURE.md` — do not use these outside local dev).

## Project structure

See `ARCHITECTURE.md` section 6 for the full folder layout and section 3 for the database schema.

## What this module hands off to teammates

- **Member 3 (Attack Simulator):** POSTs to `/login` — no auth/API key needed.
- **Member 4 (AI Detection):** reads the `login_attempts` table (SQLite, `instance/honeypot.db`).
- **Member 5 (Threat Intelligence):** reads `login_attempts`, writes back into the `country` column.
- **Member 6 (Dashboard):** reads both `users` and `login_attempts` read-only.

## Status

- [x] Fake banking UI (home, login, forgot password, dashboard, transactions, profile)
- [x] Flask backend + authentication
- [x] Honeypot logger (every login attempt persisted)
- [x] SQLite DB + schema
- [ ] Rate limiting / account lockout — intentionally **not** implemented (honeypot needs the full attack, see ARCHITECTURE.md §7)
