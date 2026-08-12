"""
============================================================================
 MEMBER 5 — THREAT INTELLIGENCE  |  File 1 of 2: GeoIP Enrichment
============================================================================
WHAT THIS DOES (in one line):
    Reads every login attempt, works out which COUNTRY each attacker IP
    came from, and fills in the `country` column that Member 1/2 left empty.

WHERE IT SITS IN THE PIPELINE:
    Members 2 & 3 write login attempts  ->  [THIS SCRIPT adds country]  ->
    threat_intel.py builds the report   ->  Member 6 dashboard shows it.

WHY THE `country` COLUMN ALREADY EXISTS:
    app/models.py defines `country = db.Column(..., nullable=True)` and
    ARCHITECTURE.md section 3 says: "left NULL - Member 5 fills this via
    GeoIP in a later pass". THIS is that pass.

TWO DATA SOURCES (pick with --source):
    sqlite : the real database instance/honeypot.db (once Members 2+3 run)
    csv    : Member 4's sample file, so YOU can build & test RIGHT NOW
             even before the real DB exists.

IMPORTANT HONESTY NOTE (read this):
    Every IP in the current demo/sample data is a PRIVATE address
    (192.168.x.x, 10.0.x.x). Private IPs are NOT on the public internet,
    so GeoIP genuinely cannot map them to a real country -- that is a fact
    about how IP geolocation works, not a bug in this script. Such IPs are
    labelled "Private/Local Network" by default.
    If you need the demo dashboard to show a coloured world map anyway,
    pass --demo-geo. That assigns SYNTHETIC (fake-but-consistent) countries
    to private IPs purely so the demo looks alive. It is OFF by default,
    prints a loud warning, and is clearly recorded so nobody mistakes it
    for real geolocation.

USAGE EXAMPLES:
    # Test on the sample CSV right now (no real DB needed):
    python geoip_enrich.py --source csv

    # Real run once instance/honeypot.db has data:
    python geoip_enrich.py --source sqlite

    # Real run, but give private demo IPs synthetic countries for the demo:
    python geoip_enrich.py --source sqlite --demo-geo

    # See what WOULD happen without writing anything:
    python geoip_enrich.py --source csv --dry-run

All behaviour is controlled by flags below (run with -h to see them all)
so you never have to edit the code to change how it runs.
============================================================================
"""

import argparse
import csv
import hashlib
import ipaddress
import os
import sqlite3
import sys

# --------------------------------------------------------------------------
# Path defaults. This file lives in <project>/threat_intelligence/, so the
# project root is one level up. We resolve everything relative to that, so
# the script works no matter which folder you run it from.
# --------------------------------------------------------------------------
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(THIS_DIR, ".."))

DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "instance", "honeypot.db")
DEFAULT_CSV_IN = os.path.join(
    PROJECT_ROOT, "ai_detection_engine", "data", "login_attempts_sample.csv"
)
DEFAULT_CSV_OUT = os.path.join(THIS_DIR, "output", "login_attempts_enriched.csv")
DEFAULT_GEOIP_DB = os.path.join(THIS_DIR, "data", "GeoLite2-Country.mmdb")

# Fixed pool used ONLY by --demo-geo to hand synthetic countries to private
# IPs. Kept small and obvious so it reads as "demo data" at a glance.
DEMO_COUNTRY_POOL = [
    "India", "United States", "Russia", "China", "Brazil",
    "Germany", "Nigeria", "Vietnam", "Netherlands", "Indonesia",
]


# --------------------------------------------------------------------------
# IP classification helpers
# --------------------------------------------------------------------------
def classify_ip(ip_str):
    """Return one of: 'public', 'private', 'invalid'.

    'private' covers anything not routable on the public internet
    (private ranges, loopback/localhost, link-local, reserved) -- GeoIP
    cannot resolve these to a real country, and that's expected.
    """
    if not ip_str:
        return "invalid"
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return "invalid"
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return "private"
    return "public"


def demo_country_for(ip_str):
    """Deterministically map an IP to a country from DEMO_COUNTRY_POOL.

    Deterministic = the same IP always gets the same country, so charts are
    stable across runs. This is SYNTHETIC data for demo visuals only.
    """
    digest = hashlib.md5(ip_str.encode("utf-8")).hexdigest()
    idx = int(digest, 16) % len(DEMO_COUNTRY_POOL)
    return DEMO_COUNTRY_POOL[idx]


# --------------------------------------------------------------------------
# GeoIP reader (real geolocation for PUBLIC IPs)
# --------------------------------------------------------------------------
class GeoIPResolver:
    """Thin wrapper around the MaxMind geoip2 reader.

    Degrades gracefully: if the geoip2 library isn't installed or the
    .mmdb database file isn't downloaded yet, the script STILL runs -- it
    just labels public IPs as the unknown-label instead of crashing. That
    lets you test the whole pipeline before doing the manual MaxMind step.
    """

    def __init__(self, mmdb_path, unknown_label):
        self.unknown_label = unknown_label
        self.reader = None
        self.available = False
        self.reason = ""

        try:
            import geoip2.database  # noqa: F401
        except ImportError:
            self.reason = "geoip2 library not installed (pip install geoip2)"
            return

        if not os.path.exists(mmdb_path):
            self.reason = f"GeoLite2 database not found at {mmdb_path}"
            return

        try:
            import geoip2.database
            self.reader = geoip2.database.Reader(mmdb_path)
            self.available = True
        except Exception as exc:  # pragma: no cover - defensive
            self.reason = f"could not open GeoLite2 database: {exc}"

    def country_for(self, ip_str):
        """Real country name for a PUBLIC ip, or unknown_label if it can't
        be resolved. Only call this for IPs already classified 'public'."""
        if not self.available or self.reader is None:
            return self.unknown_label
        try:
            import geoip2.errors
            resp = self.reader.country(ip_str)
            return resp.country.name or self.unknown_label
        except Exception:
            # AddressNotFoundError and any other lookup issue -> unknown
            return self.unknown_label

    def close(self):
        if self.reader is not None:
            self.reader.close()


# --------------------------------------------------------------------------
# Core: turn one IP into a country label, given the chosen options
# --------------------------------------------------------------------------
def resolve_country(ip_str, resolver, opts):
    """Single source of truth for 'what country do we record for this IP'."""
    kind = classify_ip(ip_str)

    if kind == "invalid":
        return opts["unknown_label"]

    if kind == "private":
        if opts["demo_geo"]:
            return demo_country_for(ip_str)
        return opts["private_label"]

    # public IP -> real GeoIP lookup
    return resolver.country_for(ip_str)


# --------------------------------------------------------------------------
# SQLite mode -- update the real login_attempts.country column in place
# --------------------------------------------------------------------------
def enrich_sqlite(opts, resolver):
    db_path = opts["db_path"]
    if not os.path.exists(db_path):
        print(f"[ERROR] Database not found: {db_path}")
        print("        Members 2 & 3 need to run first, OR test on the sample")
        print("        data now with:  python geoip_enrich.py --source csv")
        return 1

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Only look up each DISTINCT ip once (an attacker IP appears in hundreds
    # of rows -- resolving it once and reusing is the correct, efficient way).
    if opts["overwrite"]:
        cur.execute("SELECT DISTINCT ip_address FROM login_attempts")
    else:
        cur.execute(
            "SELECT DISTINCT ip_address FROM login_attempts "
            "WHERE country IS NULL OR country = ''"
        )
    ips = [r["ip_address"] for r in cur.fetchall()]

    if not ips:
        print("[OK] Nothing to do -- every row already has a country.")
        print("     (Use --overwrite to re-resolve all rows anyway.)")
        conn.close()
        return 0

    summary = {"public": 0, "private": 0, "invalid": 0}
    ip_to_country = {}
    for ip in ips:
        ip_to_country[ip] = resolve_country(ip, resolver, opts)
        summary[classify_ip(ip)] += 1

    print(f"Resolving {len(ips)} distinct IP(s)...")
    _print_ip_table(ip_to_country)

    if opts["dry_run"]:
        print("\n[DRY RUN] No changes written to the database.")
        conn.close()
        return 0

    updated_rows = 0
    for ip, country in ip_to_country.items():
        if opts["overwrite"]:
            cur.execute(
                "UPDATE login_attempts SET country = ? WHERE ip_address = ?",
                (country, ip),
            )
        else:
            cur.execute(
                "UPDATE login_attempts SET country = ? "
                "WHERE ip_address = ? AND (country IS NULL OR country = '')",
                (country, ip),
            )
        updated_rows += cur.rowcount
    conn.commit()
    conn.close()

    _print_summary(summary, updated_rows, "rows updated in login_attempts", opts)
    return 0


# --------------------------------------------------------------------------
# CSV mode -- read Member 4's sample, add a country column, write a new file
# (never overwrites the source CSV; that file belongs to Member 4)
# --------------------------------------------------------------------------
def enrich_csv(opts, resolver):
    csv_in = opts["csv_path"]
    csv_out = opts["csv_out"]
    if not os.path.exists(csv_in):
        print(f"[ERROR] Sample CSV not found: {csv_in}")
        return 1

    with open(csv_in, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])

    if "country" not in fieldnames:
        fieldnames.append("country")

    summary = {"public": 0, "private": 0, "invalid": 0}
    cache = {}
    for row in rows:
        ip = row.get("ip_address", "")
        if ip not in cache:
            cache[ip] = resolve_country(ip, resolver, opts)
            summary[classify_ip(ip)] += 1
        row["country"] = cache[ip]

    print(f"Resolved {len(cache)} distinct IP(s) across {len(rows)} rows.")
    _print_ip_table(cache)

    if opts["dry_run"]:
        print("\n[DRY RUN] No output file written.")
        return 0

    os.makedirs(os.path.dirname(csv_out), exist_ok=True)
    with open(csv_out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    _print_summary(summary, len(rows), f"rows written to {csv_out}", opts)
    return 0


# --------------------------------------------------------------------------
# Pretty output helpers
# --------------------------------------------------------------------------
def _print_ip_table(ip_to_country):
    print("\n  IP address           -> country")
    print("  " + "-" * 44)
    for ip, country in sorted(ip_to_country.items()):
        print(f"  {ip:<20} -> {country}")


def _print_summary(summary, affected, affected_label, opts):
    print("\n" + "=" * 60)
    print("GEOIP ENRICHMENT SUMMARY")
    print("=" * 60)
    print(f"  Public IPs (real GeoIP)   : {summary['public']}")
    print(f"  Private/local IPs         : {summary['private']}")
    print(f"  Invalid/blank IPs         : {summary['invalid']}")
    print(f"  {affected_label:<26}: {affected}")
    if opts["demo_geo"]:
        print("\n  " + "!" * 56)
        print("  ! DEMO-GEO WAS ON: private IPs were given SYNTHETIC       !")
        print("  ! countries for demo visuals only. These are NOT real     !")
        print("  ! geolocations. Do not present them as real attribution.  !")
        print("  " + "!" * 56)
    print("=" * 60)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        description="Member 5 Threat Intelligence: fill the country column "
                    "for each login attempt using GeoIP.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--source", choices=["sqlite", "csv"], default="sqlite",
                   help="Where to read login attempts from.")
    p.add_argument("--db-path", default=DEFAULT_DB_PATH,
                   help="SQLite DB path (used when --source sqlite).")
    p.add_argument("--csv-path", default=DEFAULT_CSV_IN,
                   help="Input CSV path (used when --source csv).")
    p.add_argument("--csv-out", default=DEFAULT_CSV_OUT,
                   help="Where to write the enriched CSV (csv mode).")
    p.add_argument("--geoip-db", default=DEFAULT_GEOIP_DB,
                   help="Path to MaxMind GeoLite2-Country.mmdb.")
    p.add_argument("--private-label", default="Private/Local Network",
                   help="Label recorded for private/local IPs.")
    p.add_argument("--unknown-label", default="Unknown",
                   help="Label recorded when a public IP can't be resolved.")
    p.add_argument("--demo-geo", action="store_true",
                   help="Assign SYNTHETIC countries to private IPs so demo "
                        "visuals look alive. Off by default. Not real geo.")
    p.add_argument("--overwrite", action="store_true",
                   help="Re-resolve rows that already have a country "
                        "(default: only fill empty ones).")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would happen without writing anything.")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    opts = {
        "source": args.source,
        "db_path": args.db_path,
        "csv_path": args.csv_path,
        "csv_out": args.csv_out,
        "private_label": args.private_label,
        "unknown_label": args.unknown_label,
        "demo_geo": args.demo_geo,
        "overwrite": args.overwrite,
        "dry_run": args.dry_run,
    }

    resolver = GeoIPResolver(args.geoip_db, args.unknown_label)
    if resolver.available:
        print(f"[GeoIP] Using real database: {args.geoip_db}")
    else:
        print(f"[GeoIP] Real geolocation OFF -- {resolver.reason}.")
        print("        Public IPs will be labelled "
              f"'{args.unknown_label}'. Private IPs are unaffected.")
        if args.source == "csv":
            print("        (That's fine for testing -- the sample data is "
                  "all private IPs anyway.)")

    try:
        if args.source == "sqlite":
            rc = enrich_sqlite(opts, resolver)
        else:
            rc = enrich_csv(opts, resolver)
    finally:
        resolver.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
