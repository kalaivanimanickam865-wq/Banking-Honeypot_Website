"""
============================================================================
 MEMBER 5 — THREAT INTELLIGENCE  |  File 2 of 2: Threat Report Builder
============================================================================
WHAT THIS DOES (in one line):
    Reads every (enriched) login attempt and produces threat_intel.json --
    the single file you hand to Member 6 for the dashboard.

WHERE IT SITS IN THE PIPELINE:
    Members 2 & 3 write login attempts
      -> geoip_enrich.py adds the `country` column   (File 1)
      -> [THIS SCRIPT reads it all and builds the report]   (File 2)
      -> Member 6 dashboard reads threat_intel.json and draws the charts.

THE 6 THINGS THIS REPORT ANSWERS (from the project flowchart):
    1. Top Attacker IP        -> "top_attacker_ips"
    2. Attack Country         -> "countries"
    3. Attack Timeline        -> "timeline"
    4. Peak Attack Hour       -> "peak_hour"
    5. Most Targeted Username -> "targeted_usernames"
    6. Password Statistics    -> "password_stats"

TWO DATA SOURCES (pick with --source), matching geoip_enrich.py:
    sqlite : the real database instance/honeypot.db (once Members 2+3 run).
             Reads the `country` column that File 1 already filled in place.
    csv    : the ENRICHED csv that File 1 wrote
             (threat_intelligence/output/login_attempts_enriched.csv),
             so you can build & test the report RIGHT NOW.

NO EXTERNAL LIBRARIES NEEDED. Pure Python standard library, so this runs
with zero `pip install` on the sample data.

USAGE EXAMPLES:
    # Build the report from the enriched sample CSV (works right now):
    python threat_intel.py --source csv

    # Build from the real DB once it has enriched data:
    python threat_intel.py --source sqlite

    # Show more entries in each ranked list and print a readable summary:
    python threat_intel.py --source csv --top-n 20 --print-summary

All behaviour is controlled by flags (run with -h) so you never edit code.
============================================================================
"""

import argparse
import csv
import json
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))

DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "instance", "honeypot.db")
DEFAULT_ENRICHED_CSV = os.path.join(THIS_DIR, "output", "login_attempts_enriched.csv")
DEFAULT_OUT = os.path.join(THIS_DIR, "output", "threat_intel.json")

REPORT_VERSION = "1.0"
PRIVATE_LABEL = "Private/Local Network"

# Columns this report reads. Every one exists in app/models.py's
# login_attempts table (and in the enriched CSV File 1 produces).
NEEDED_COLUMNS = [
    "username_attempted", "password_attempted", "ip_address",
    "timestamp", "login_status", "country", "session_id",
]


# --------------------------------------------------------------------------
# Loading -- both sources normalise to the same list[dict] shape
# --------------------------------------------------------------------------
def load_rows_sqlite(db_path):
    if not os.path.exists(db_path):
        raise FileNotFoundError(
            f"Database not found: {db_path}\n"
            "        Members 2 & 3 need to run first, OR build the report from\n"
            "        the enriched sample now with:  python threat_intel.py --source csv"
        )
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Only select columns we know exist; guards against a schema drift.
    cur.execute("PRAGMA table_info(login_attempts)")
    existing = {r[1] for r in cur.fetchall()}
    cols = [c for c in NEEDED_COLUMNS if c in existing]
    cur.execute(f"SELECT {', '.join(cols)} FROM login_attempts")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def load_rows_csv(csv_path):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"Enriched CSV not found: {csv_path}\n"
            "        Run File 1 first:  python geoip_enrich.py --source csv"
        )
    with open(csv_path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# --------------------------------------------------------------------------
# Timestamp parsing -- robust across the formats these tools emit
# --------------------------------------------------------------------------
def parse_timestamp(value):
    """Return a datetime or None. Handles ISO with space or 'T', with or
    without microseconds. Never raises -- unparseable timestamps are just
    left out of the timeline rather than crashing the whole report."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip().replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1]
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def is_failed(row):
    return (row.get("login_status") or "").lower() == "failed"


# --------------------------------------------------------------------------
# The report sections (one function each -- clear boundaries)
# --------------------------------------------------------------------------
def build_summary(rows):
    total = len(rows)
    failed = sum(1 for r in rows if is_failed(r))
    success = total - failed
    ips = {r.get("ip_address") for r in rows if r.get("ip_address")}
    usernames = {r.get("username_attempted") for r in rows if r.get("username_attempted")}

    times = [parse_timestamp(r.get("timestamp")) for r in rows]
    times = [t for t in times if t is not None]
    first = min(times).isoformat() if times else None
    last = max(times).isoformat() if times else None

    return {
        "total_attempts": total,
        "failed_attempts": failed,
        "successful_attempts": success,
        "failure_rate_pct": round(100 * failed / total, 2) if total else 0.0,
        "unique_ips": len(ips),
        "unique_usernames_targeted": len(usernames),
        "first_attempt": first,
        "last_attempt": last,
    }


def build_top_attacker_ips(rows, top_n):
    """#1 Top Attacker IP -- ranked by total attempts, with fail/success
    split and the country File 1 resolved for that IP."""
    per_ip_total = Counter()
    per_ip_failed = Counter()
    ip_country = {}
    for r in rows:
        ip = r.get("ip_address")
        if not ip:
            continue
        per_ip_total[ip] += 1
        if is_failed(r):
            per_ip_failed[ip] += 1
        ip_country.setdefault(ip, r.get("country") or "")

    out = []
    for ip, total in per_ip_total.most_common(top_n):
        out.append({
            "ip_address": ip,
            "country": ip_country.get(ip, ""),
            "total_attempts": total,
            "failed_attempts": per_ip_failed[ip],
            "successful_attempts": total - per_ip_failed[ip],
        })
    return out


def build_countries(rows, top_n):
    """#2 Attack Country -- attempts grouped by the enriched country label."""
    per_country_total = Counter()
    per_country_failed = Counter()
    for r in rows:
        country = r.get("country") or "Unlabelled"
        per_country_total[country] += 1
        if is_failed(r):
            per_country_failed[country] += 1

    out = []
    for country, total in per_country_total.most_common(top_n):
        out.append({
            "country": country,
            "attempts": total,
            "failed_attempts": per_country_failed[country],
        })
    # Honest flag: if every country is the private label, geo is not
    # meaningful yet (all-private data). Member 6 can show a note.
    only_private = set(per_country_total) <= {PRIVATE_LABEL, "Unlabelled", "Unknown"}
    return out, only_private


def build_timeline(rows):
    """#3 Attack Timeline -- attempts per hour bucket, chronological."""
    per_bucket_total = Counter()
    per_bucket_failed = Counter()
    for r in rows:
        t = parse_timestamp(r.get("timestamp"))
        if t is None:
            continue
        bucket = t.strftime("%Y-%m-%d %H:00")
        per_bucket_total[bucket] += 1
        if is_failed(r):
            per_bucket_failed[bucket] += 1

    return [
        {"bucket": b, "attempts": per_bucket_total[b], "failed_attempts": per_bucket_failed[b]}
        for b in sorted(per_bucket_total)
    ]


def build_peak_hour(rows):
    """#4 Peak Attack Hour -- both the busiest hour-of-day (0-23) aggregated
    across all days, and the single busiest timestamp bucket."""
    hour_of_day = Counter()
    bucket_total = Counter()
    for r in rows:
        t = parse_timestamp(r.get("timestamp"))
        if t is None:
            continue
        hour_of_day[t.hour] += 1
        bucket_total[t.strftime("%Y-%m-%d %H:00")] += 1

    distribution = [{"hour": h, "attempts": hour_of_day.get(h, 0)} for h in range(24)]
    peak_hod = max(hour_of_day, key=hour_of_day.get) if hour_of_day else None
    busiest_bucket = max(bucket_total, key=bucket_total.get) if bucket_total else None

    return {
        "peak_hour_of_day": peak_hod,
        "peak_hour_of_day_attempts": hour_of_day.get(peak_hod, 0) if peak_hod is not None else 0,
        "busiest_time_bucket": busiest_bucket,
        "busiest_time_bucket_attempts": bucket_total.get(busiest_bucket, 0) if busiest_bucket else 0,
        "hour_of_day_distribution": distribution,
    }


def build_targeted_usernames(rows, top_n):
    """#5 Most Targeted Username -- usernames ranked by attempts against them."""
    per_user_total = Counter()
    per_user_failed = Counter()
    for r in rows:
        u = r.get("username_attempted")
        if u is None or u == "":
            u = "(blank)"
        per_user_total[u] += 1
        if is_failed(r):
            per_user_failed[u] += 1

    out = []
    for user, total in per_user_total.most_common(top_n):
        out.append({
            "username": user,
            "attempts": total,
            "failed_attempts": per_user_failed[user],
        })
    return out


def build_password_stats(rows, top_n):
    """#6 Password Statistics -- most-guessed passwords + basic patterns."""
    pw_counter = Counter()
    length_counter = Counter()
    for r in rows:
        pw = r.get("password_attempted")
        if pw is None:
            continue
        pw_counter[pw] += 1
        length_counter[len(pw)] += 1

    top_passwords = [
        {"password": pw, "count": c} for pw, c in pw_counter.most_common(top_n)
    ]
    most_common_length = length_counter.most_common(1)[0][0] if length_counter else None
    return {
        "unique_passwords": len(pw_counter),
        "most_common_password": pw_counter.most_common(1)[0][0] if pw_counter else None,
        "most_common_password_length": most_common_length,
        "top_passwords": top_passwords,
    }


# --------------------------------------------------------------------------
# Assemble the full report
# --------------------------------------------------------------------------
def build_report(rows, source, source_path, top_n):
    countries, only_private = build_countries(rows, top_n)
    report = {
        "meta": {
            "tool": "Member 5 - Threat Intelligence",
            "report_version": REPORT_VERSION,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "source": source,
            "source_path": source_path,
            "records_analysed": len(rows),
            "geo_note": (
                "All IPs are private/local, so country data is not real "
                "geolocation. Re-run geoip_enrich.py with --demo-geo for "
                "synthetic demo countries, or feed real public-IP data."
                if only_private else
                "Country values come from GeoIP enrichment (geoip_enrich.py)."
            ),
        },
        "summary": build_summary(rows),
        "top_attacker_ips": build_top_attacker_ips(rows, top_n),
        "countries": countries,
        "timeline": build_timeline(rows),
        "peak_hour": build_peak_hour(rows),
        "targeted_usernames": build_targeted_usernames(rows, top_n),
        "password_stats": build_password_stats(rows, top_n),
    }
    return report


def print_summary(report):
    s = report["summary"]
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE SUMMARY (Member 5)")
    print("=" * 60)
    print(f"  Records analysed        : {report['meta']['records_analysed']}")
    print(f"  Total / failed / success: {s['total_attempts']} / "
          f"{s['failed_attempts']} / {s['successful_attempts']}")
    print(f"  Failure rate            : {s['failure_rate_pct']}%")
    print(f"  Unique IPs              : {s['unique_ips']}")
    print(f"  Unique usernames hit    : {s['unique_usernames_targeted']}")
    if report["top_attacker_ips"]:
        top = report["top_attacker_ips"][0]
        print(f"  #1 attacker IP          : {top['ip_address']} "
              f"({top['total_attempts']} attempts, {top['country']})")
    if report["targeted_usernames"]:
        tu = report["targeted_usernames"][0]
        print(f"  Most targeted username  : {tu['username']} ({tu['attempts']} attempts)")
    ph = report["peak_hour"]
    print(f"  Peak hour of day        : {ph['peak_hour_of_day']}:00 "
          f"({ph['peak_hour_of_day_attempts']} attempts)")
    pw = report["password_stats"]
    print(f"  Most-guessed password   : {pw['most_common_password']!r} "
          f"({pw['unique_passwords']} unique passwords seen)")
    print("=" * 60)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Member 5 Threat Intelligence: build threat_intel.json "
                    "from enriched login attempts.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--source", choices=["sqlite", "csv"], default="sqlite",
                   help="Where to read login attempts from.")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH,
                   help="SQLite DB path (used when --source sqlite).")
    p.add_argument("--csv-path", default=DEFAULT_ENRICHED_CSV,
                   help="Enriched CSV path from File 1 (used when --source csv).")
    p.add_argument("--out", default=DEFAULT_OUT,
                   help="Where to write threat_intel.json.")
    p.add_argument("--top-n", type=int, default=10,
                   help="How many entries to keep in each ranked list.")
    p.add_argument("--print-summary", action="store_true",
                   help="Also print a human-readable summary to the console.")
    p.add_argument("--dry-run", action="store_true",
                   help="Build the report but don't write the JSON file.")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        if args.source == "sqlite":
            rows = load_rows_sqlite(args.db_path)
            source_path = args.db_path
        else:
            rows = load_rows_csv(args.csv_path)
            source_path = args.csv_path
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        return 1

    if not rows:
        print("[WARN] No login attempts found -- nothing to report on yet.")
        return 0

    report = build_report(rows, args.source, source_path, args.top_n)

    if args.print_summary:
        print_summary(report)

    if args.dry_run:
        print("\n[DRY RUN] Report built but not written.")
        return 0

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Threat intelligence report written to:\n     {args.out}")
    print("     -> This is the file you hand to Member 6 (Dashboard).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
