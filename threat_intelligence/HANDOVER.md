# MEMBER 5 — THREAT INTELLIGENCE  ✅ DONE

**Status:** COMPLETE and verified against the sample dataset (1,990 login attempts).
**Owner:** Member 5
**Hands off to:** Member 6 (Dashboard & Integration)
**Part of:** AI-Powered Banking Honeypot for Brute-Force Detection & Threat Intelligence

---

## 1. What this module does (plain English)

Every login attempt (real or attacker) is written to the honeypot's
`login_attempts` table by Members 2 & 3. This module is the **detective**:
it reads all those attempts and produces a single threat-intelligence
report answering the 6 questions from the project flowchart:

| # | Flowchart item | Where it is in the JSON |
|---|---|---|
| 1 | Top Attacker IP | `top_attacker_ips` |
| 2 | Attack Country | `countries` |
| 3 | Attack Timeline | `timeline` |
| 4 | Peak Attack Hour | `peak_hour` |
| 5 | Most Targeted Username | `targeted_usernames` |
| 6 | Password Statistics | `password_stats` |

---

## 2. Files in this module

```
threat_intelligence/
├── geoip_enrich.py     # FILE 1: fills the `country` column via GeoIP
├── threat_intel.py     # FILE 2: builds threat_intel.json (the deliverable)
├── requirements.txt    # geoip2 (only for real public IPs), optional pandas
├── HANDOVER.md         # this file
├── data/
│   └── GeoLite2-Country.mmdb   # (you download this — see §5; not committed)
└── output/
    ├── login_attempts_enriched.csv   # intermediate (File 1 output, csv mode)
    └── threat_intel.json             # >>> THE DELIVERABLE for Member 6 <<<
```

---

## 3. How to run (two steps)

Both scripts read from either the live database (`--source sqlite`) or the
sample CSV (`--source csv`). Everything is a flag — no code editing needed.

```bash
# Step 1 — add the country column to every login attempt
python geoip_enrich.py --source csv        # or: --source sqlite

# Step 2 — build the threat report from the enriched data
python threat_intel.py --source csv --print-summary   # or: --source sqlite
```

`--source csv` works right now on the sample data.
`--source sqlite` is the real run once Members 2 & 3 have populated
`instance/honeypot.db`. Switching is just changing that one flag.

Useful flags:
- `--top-n 20` — keep more entries in each ranked list (default 10)
- `--demo-geo` (File 1 only) — give private demo IPs synthetic countries so
  the dashboard map looks alive (clearly labelled as NOT real geolocation)
- `--dry-run` — show what would happen without writing anything
- `-h` — full flag list

---

## 4. THE HANDOFF CONTRACT (what Member 6 consumes)

**Member 6 reads exactly one file:**
`threat_intelligence/output/threat_intel.json`

It is plain JSON with this stable top-level shape (Member 6 can rely on
these keys not changing):

```
{
  "meta":               { tool, report_version, generated_at, source,
                          source_path, records_analysed, geo_note },
  "summary":            { total_attempts, failed_attempts,
                          successful_attempts, failure_rate_pct,
                          unique_ips, unique_usernames_targeted,
                          first_attempt, last_attempt },
  "top_attacker_ips":   [ { ip_address, country, total_attempts,
                            failed_attempts, successful_attempts }, ... ],
  "countries":          [ { country, attempts, failed_attempts }, ... ],
  "timeline":           [ { bucket, attempts, failed_attempts }, ... ],
  "peak_hour":          { peak_hour_of_day, peak_hour_of_day_attempts,
                          busiest_time_bucket, busiest_time_bucket_attempts,
                          hour_of_day_distribution: [ {hour, attempts} x24 ] },
  "targeted_usernames": [ { username, attempts, failed_attempts }, ... ],
  "password_stats":     { unique_passwords, most_common_password,
                          most_common_password_length,
                          top_passwords: [ {password, count}, ... ] }
}
```

**Member 6, to load it in Streamlit:**
```python
import json
with open("threat_intelligence/output/threat_intel.json") as f:
    ti = json.load(f)

ti["summary"]["total_attempts"]            # a big-number metric card
ti["top_attacker_ips"]                     # a bar chart / table
ti["countries"]                            # a map or bar chart
ti["timeline"]                             # a line chart over time
ti["peak_hour"]["hour_of_day_distribution"]# a 24-bar "busiest hour" chart
ti["targeted_usernames"]                   # a table
ti["password_stats"]["top_passwords"]      # a table / word list
```

To refresh with the latest attacks, Member 6 (or a scheduler) just re-runs
the two commands in §3 with `--source sqlite`; the JSON is overwritten.

---

## 5. IMPORTANT — the country data caveat (read before the demo)

Every IP in the current sample/simulator data is a **private address**
(`192.168.x.x`, `10.0.x.x`). Private IPs are not on the public internet, so
GeoIP genuinely cannot map them to a real country — so `country` comes out
as `"Private/Local Network"`, and `meta.geo_note` says so.

Two honest options for the demo:
1. **Show it truthfully** — Member 6 displays the geo_note and a
   "local traffic" label instead of a world map.
2. **Synthetic demo geo** — re-run File 1 with `--demo-geo`. Private IPs get
   consistent fake countries so the map looks alive. This is opt-in, prints
   a loud warning, and must never be presented as real attribution.

For **real** geolocation of real public attacker IPs (later / production):
- Manual step: make a free MaxMind account, download `GeoLite2-Country.mmdb`,
  and place it at `threat_intelligence/data/GeoLite2-Country.mmdb`.
- `pip install geoip2`
- Re-run File 1 with `--source sqlite`. Public IPs then resolve to real
  countries automatically; private ones stay labelled as local.

---

## 6. Verification status

- [x] File 1 runs on sample CSV (283 IPs, 1,990 rows) — country column filled
- [x] File 1 runs on real SQLite schema — only `country` written, other
      columns untouched, safe to re-run (skips already-filled rows)
- [x] File 2 runs on sample CSV and on SQLite — all 6 sections produced
- [x] `threat_intel.json` generated and validated
- [x] Handoff contract documented for Member 6 (§4)

**Member 5 is complete. Baton passed to Member 6.** 🏁
