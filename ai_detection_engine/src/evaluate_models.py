import os

import joblib
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


def evaluate_models():
    # Load trained models and test data
    rf_model = joblib.load(
        os.path.join(MODEL_DIR, "random_forest_model.pkl")
    )

    xgb_model = joblib.load(
        os.path.join(MODEL_DIR, "xgboost_model.pkl")
    )

    X_test, y_test = joblib.load(
        os.path.join(MODEL_DIR, "test_split.pkl")
    )

    # Random Forest predictions
    rf_predictions = rf_model.predict(X_test)

    # XGBoost predictions
    xgb_predictions = xgb_model.predict(X_test)

    # Random Forest evaluation
    print("\n" + "=" * 60)
    print("RANDOM FOREST RESULTS")
    print("=" * 60)

    print(f"Accuracy: {accuracy_score(y_test, rf_predictions):.4f}")

    print("\nClassification Report:")
    print(classification_report(y_test, rf_predictions))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, rf_predictions))

    # XGBoost evaluation
    print("\n" + "=" * 60)
    print("XGBOOST RESULTS")
    print("=" * 60)

    print(f"Accuracy: {accuracy_score(y_test, xgb_predictions):.4f}")

    print("\nClassification Report:")
    print(classification_report(y_test, xgb_predictions))

    print("Confusion Matrix:")
    print(confusion_matrix(y_test, xgb_predictions))


if __name__ == "__main__":
    evaluate_models()