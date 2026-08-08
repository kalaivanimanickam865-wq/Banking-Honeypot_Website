import sqlite3

import pandas as pd

REQUIRED_COLUMNS = [
    "username_attempted",
    "ip_address",
    "timestamp",
    "login_status",
    "session_id",
]


def load_from_csv(path="data/login_attempts_sample.csv") -> pd.DataFrame:
    """Load the simulated dataset (has an extra 'label' column used for
    training only — a real pull from the live DB won't have this)."""
    df = pd.read_csv(path, parse_dates=["timestamp"])
    return df


def load_from_sqlite(db_path, table="login_attempts", limit=None) -> pd.DataFrame:
    """Load real rows from Member 2/3's SQLite database.

    Example (once instance/honeypot.db exists):
        df = load_from_sqlite("../instance/honeypot.db")

    There's no 'label' column here — the live table isn't hand-labeled,
    so this path is used for PREDICTION, not for retraining.
    """
    query = f"SELECT * FROM {table}"
    if limit:
        query += f" LIMIT {int(limit)}"

    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query(query, conn, parse_dates=["timestamp"])
    finally:
        conn.close()

    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"login_attempts table is missing expected columns: {missing}")

    return df


if __name__ == "__main__":
    df = load_from_csv()
    print(df.head())
    print(f"\nLoaded {len(df)} rows from CSV")