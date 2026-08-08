import os
import sys

import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

sys.path.insert(0, os.path.dirname(__file__))
from data_loader import load_from_csv
from feature_engineering import engineer_features, get_feature_target

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "login_attempts_sample.csv")


def train_and_save_models():
    # 1. Load simulated data + engineer behavioral features
    df = load_from_csv(DATA_PATH)
    df = engineer_features(df)
    X, y, feature_cols = get_feature_target(df)

    # 2. Train/test split (stratify keeps the normal/brute_force ratio balanced in both sets)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # 3. Random Forest
    rf_model = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42)
    rf_model.fit(X_train, y_train)

    # 4. XGBoost
    xgb_model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        eval_metric="logloss",
        random_state=42,
    )
    xgb_model.fit(X_train, y_train)

    # 5. Save everything evaluate_models.py needs next
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(rf_model, os.path.join(MODEL_DIR, "random_forest_model.pkl"))
    joblib.dump(xgb_model, os.path.join(MODEL_DIR, "xgboost_model.pkl"))
    joblib.dump(feature_cols, os.path.join(MODEL_DIR, "feature_columns.pkl"))
    joblib.dump((X_test, y_test), os.path.join(MODEL_DIR, "test_split.pkl"))

    print("Random Forest and XGBoost models trained and saved to /models")
    return rf_model, xgb_model, X_test, y_test, feature_cols


if __name__ == "__main__":
    train_and_save_models()

