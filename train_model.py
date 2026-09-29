"""
train_model.py

Trains a RandomForestClassifier on the generated URL dataset using
features from feature_extractor.py, evaluates it, and saves the
trained model + feature list to models/ for use by app.py.
"""

import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from feature_extractor import extract_features, FEATURE_NAMES


def build_feature_matrix(urls):
    rows = [extract_features(u) for u in urls]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)


def main():
    df = pd.read_csv("data/urls.csv")
    print(f"Loaded {len(df)} rows")

    X = build_feature_matrix(df["url"])
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    print("\n=== Evaluation on held-out test set ===")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1-score:  {f1:.4f}")
    print("\nConfusion matrix (rows=actual, cols=predicted) [legit, phishing]:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    # Feature importance (nice to show the teacher)
    importances = pd.Series(model.feature_importances_, index=FEATURE_NAMES)
    importances = importances.sort_values(ascending=False)
    print("\nTop 10 most important features:")
    print(importances.head(10))

    joblib.dump(model, "models/phishing_url_model.joblib")
    joblib.dump(FEATURE_NAMES, "models/feature_names.joblib")
    print("\nSaved model to models/phishing_url_model.joblib")


if __name__ == "__main__":
    main()
