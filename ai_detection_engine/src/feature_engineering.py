import numpy as np
import pandas as pd

FEATURE_COLUMNS = [
    "login_success",
    "attempts_last_1min",
    "attempts_last_5min",
    "failed_attempts_last_10min",
    "unique_usernames_from_ip_10min",
    "time_since_last_attempt_sec",
    "failure_ratio_5min",
    "attempt_speed",
]


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    For every login attempt, compute rolling behavioral stats using ONLY
    attempts from the same ip_address that happened at or before it.
    This mirrors how detection would work in real time: you only ever
    know what's already happened, never the future.
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(["ip_address", "timestamp"]).reset_index(drop=True)

    df["login_success"] = (df["login_status"] == "success").astype(int)
    df["is_failed"] = (df["login_status"] == "failed").astype(int)

    computed_rows = []

    for ip_address, group in df.groupby("ip_address"):
        group = group.sort_values("timestamp").reset_index()
        timestamps = group["timestamp"].to_numpy()
        usernames = group["username_attempted"].to_numpy()
        is_failed = group["is_failed"].to_numpy()
        n = len(group)

        for i in range(n):
            t = timestamps[i]

            mask_1min = (timestamps <= t) & (timestamps > t - np.timedelta64(60, "s"))
            mask_5min = (timestamps <= t) & (timestamps > t - np.timedelta64(300, "s"))
            mask_10min = (timestamps <= t) & (timestamps > t - np.timedelta64(600, "s"))

            attempts_1min = int(mask_1min.sum())
            attempts_5min = int(mask_5min.sum())
            failed_10min = int(is_failed[mask_10min].sum())
            unique_usernames_10min = int(len(set(usernames[mask_10min])))

            if i == 0:
                time_since_last = 3600.0
            else:
                time_since_last = float((t - timestamps[i - 1]) / np.timedelta64(1, "s"))

            computed_rows.append({
                "orig_index": group.loc[i, "index"],
                "attempts_last_1min": attempts_1min,
                "attempts_last_5min": attempts_5min,
                "failed_attempts_last_10min": failed_10min,
                "unique_usernames_from_ip_10min": unique_usernames_10min,
                "time_since_last_attempt_sec": time_since_last,
            })

    computed_df = pd.DataFrame(computed_rows).set_index("orig_index")
    df = df.join(computed_df)

    df["failure_ratio_5min"] = df["failed_attempts_last_10min"] / (df["attempts_last_5min"] + 1)
    df["attempt_speed"] = 1 / (df["time_since_last_attempt_sec"] + 0.01)

    return df


def get_feature_target(df: pd.DataFrame):
    """Returns X (features), y (0=normal, 1=brute_force), and the feature column order."""
    X = df[FEATURE_COLUMNS]
    y = df["label"].map({"normal": 0, "brute_force": 1})
    return X, y, FEATURE_COLUMNS


if __name__ == "__main__":
    from data_loader import load_from_csv

    df = load_from_csv()
    df = engineer_features(df)
    X, y, cols = get_feature_target(df)
    print("Feature engineering complete")
    print(X.head())
    print("\nLabel counts:\n", y.value_counts())