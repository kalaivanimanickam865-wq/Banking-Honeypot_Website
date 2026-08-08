import random
import uuid
from datetime import datetime, timedelta

import pandas as pd

random.seed(42)

REAL_USERNAMES = [f"user{i}" for i in range(1, 151)]
BROWSERS = ["Chrome", "Firefox", "Edge", "Safari"]


def random_ip(prefix="192.168.1"):
    return f"{prefix}.{random.randint(2, 254)}"


def generate_normal_attempts(n_events=800, base_time=None):
    """Scattered, low-frequency logins from many different legit users/IPs."""
    base_time = base_time or datetime(2025, 1, 1, 9, 0, 0)
    rows = []
    for _ in range(n_events):
        username = random.choice(REAL_USERNAMES)
        ts = base_time + timedelta(seconds=random.randint(0, 3 * 24 * 3600))
        rows.append({
            "username_attempted": username,
            "password_attempted": "dummy_pw",
            "ip_address": random_ip("192.168.1"),
            "timestamp": ts,
            "browser": random.choice(BROWSERS),
            "user_agent": f"Mozilla/5.0 ({random.choice(BROWSERS)})",
            "session_id": uuid.uuid4().hex[:16],
            "login_status": random.choices(["success", "failed"], weights=[0.9, 0.1])[0],
            "label": "normal",
        })
    return rows


def generate_bruteforce_sessions(n_sessions=40, base_time=None):
    """Bursts: one attacker IP hammering one target username, mostly failing,
    all within a short time window — the classic brute-force signature."""
    base_time = base_time or datetime(2025, 1, 1, 9, 0, 0)
    rows = []
    for _ in range(n_sessions):
        target_user = random.choice(REAL_USERNAMES)
        attacker_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        session_id = uuid.uuid4().hex[:16]
        session_start = base_time + timedelta(seconds=random.randint(0, 3 * 24 * 3600))
        n_attempts = random.randint(15, 40)
        t = session_start
        for _ in range(n_attempts):
            t = t + timedelta(seconds=random.uniform(0.2, 3))
            rows.append({
                "username_attempted": target_user,
                "password_attempted": "guessed_pw",
                "ip_address": attacker_ip,
                "timestamp": t,
                "browser": "Script/Bot",
                "user_agent": "python-requests/2.31",
                "session_id": session_id,
                "login_status": random.choices(["success", "failed"], weights=[0.05, 0.95])[0],
                "label": "brute_force",
            })
    return rows


def generate_dataset(n_normal=800, n_bruteforce_sessions=40):
    base_time = datetime(2025, 1, 1, 9, 0, 0)
    rows = generate_normal_attempts(n_normal, base_time)
    rows += generate_bruteforce_sessions(n_bruteforce_sessions, base_time)

    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = generate_dataset()
    df.to_csv("data/login_attempts_sample.csv", index=False)
    print("Dataset created: data/login_attempts_sample.csv")
    print(f"Total rows: {len(df)}")
    print(df["label"].value_counts())