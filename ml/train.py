#!/usr/bin/env python3
"""Train a lightweight phishing domain classifier.

Trains on synthetic + real data, exports model for on-device use.
Uses scikit-learn for simplicity — the model is small enough for CoreML export.

Usage:
    python3 ml/train.py                    # generate data + train
    python3 ml/train.py --data ml/data/synthetic_domains.csv  # use existing data
"""

import argparse
import csv
import json
import os

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import cross_val_score, train_test_split

from features import FEATURE_NAMES, extract_features
from generate_synthetic import generate_dataset


def load_csv_data(path: str) -> tuple[list[str], list[int]]:
    """Load domain,label pairs from CSV."""
    domains, labels = [], []
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            domains.append(row["domain"])
            labels.append(int(row["label"]))
    return domains, labels


def extract_feature_matrix(domains: list[str]) -> np.ndarray:
    """Extract features for all domains."""
    return np.array([extract_features(d) for d in domains])


def train_and_evaluate(X: np.ndarray, y: np.ndarray, model_type: str = "gbm"):
    """Train model and print evaluation metrics."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nTraining {model_type}...")
    print(f"  Train: {len(X_train)} samples")
    print(f"  Test:  {len(X_test)} samples")

    if model_type == "gbm":
        model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            random_state=42,
        )
    elif model_type == "logistic":
        model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            C=1.0,
        )
    else:
        raise ValueError(f"Unknown model type: {model_type}")

    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    print(f"\n{'='*60}")
    print(f"Classification Report ({model_type})")
    print(f"{'='*60}")
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0][0]:5d}  FP={cm[0][1]:5d}")
    print(f"  FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")

    auc = roc_auc_score(y_test, y_prob)
    print(f"\nAUC-ROC: {auc:.4f}")

    # Cross-validation
    cv_scores = cross_val_score(model, X, y, cv=5, scoring="roc_auc")
    print(f"5-fold CV AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Feature importance
    if model_type == "gbm":
        print(f"\nTop 10 Feature Importances:")
        importances = list(zip(FEATURE_NAMES, model.feature_importances_))
        importances.sort(key=lambda x: x[1], reverse=True)
        for name, imp in importances[:10]:
            print(f"  {name:30s} {imp:.4f}")
    elif model_type == "logistic":
        print(f"\nTop 10 Feature Coefficients (absolute):")
        coeffs = list(zip(FEATURE_NAMES, model.coef_[0]))
        coeffs.sort(key=lambda x: abs(x[1]), reverse=True)
        for name, coef in coeffs[:10]:
            print(f"  {name:30s} {coef:+.4f}")

    return model


def export_model(model, model_type: str, output_dir: str = "ml/models"):
    """Export model as JSON weights for reimplementation in Swift and Python."""
    os.makedirs(output_dir, exist_ok=True)

    if model_type == "logistic":
        weights = {
            "type": "logistic_regression",
            "feature_names": FEATURE_NAMES,
            "coefficients": model.coef_[0].tolist(),
            "intercept": model.intercept_[0],
            "classes": model.classes_.tolist(),
        }
    elif model_type == "gbm":
        # Export tree structure as JSON for portable inference
        trees = []
        for i, estimators in enumerate(model.estimators_):
            tree = estimators[0].tree_
            trees.append({
                "feature": tree.feature.tolist(),
                "threshold": tree.threshold.tolist(),
                "children_left": tree.children_left.tolist(),
                "children_right": tree.children_right.tolist(),
                "value": [v[0][0] for v in tree.value.tolist()],
            })
        weights = {
            "type": "gradient_boosting",
            "feature_names": FEATURE_NAMES,
            "n_estimators": model.n_estimators,
            "learning_rate": model.learning_rate,
            "init_value": float(model.init_.class_prior_[1]),
            "trees": trees,
            "feature_importances": model.feature_importances_.tolist(),
        }

    json_path = os.path.join(output_dir, f"phishing_classifier_{model_type}.json")
    with open(json_path, "w") as f:
        json.dump(weights, f, indent=2)
    size_kb = os.path.getsize(json_path) / 1024
    print(f"\nSaved JSON model: {json_path} ({size_kb:.0f} KB)")

    return weights


def test_specific_domains(model):
    """Test the model on hand-picked domains to verify behavior."""
    test_domains = [
        # Should be phishing (high score)
        ("brou-seguro.com", True),
        ("actualizacion-brou-2026.xyz", True),
        ("verificar-itau.top", True),
        ("br0u.com.uy", True),
        ("login.santander-verificacion.click", True),
        ("homebanking-brou.net", True),
        ("itau-cuenta-suspendida.xyz", True),
        ("mercadopago-confirmar.top", True),
        # Should be legitimate (low score)
        ("google.com", False),
        ("facebook.com", False),
        ("elobservador.com.uy", False),
        ("montevideo.com.uy", False),
        ("github.com", False),
        ("wikipedia.org", False),
        ("cafe-jardin.com.uy", False),
        ("tienda-norte.com", False),
    ]

    print(f"\n{'='*60}")
    print("Spot-check on specific domains")
    print(f"{'='*60}")

    correct = 0
    for domain, expected_phishing in test_domains:
        features = np.array([extract_features(domain)])
        prob = model.predict_proba(features)[0][1]
        pred = prob >= 0.5
        match = pred == expected_phishing
        correct += int(match)
        status = "OK" if match else "MISS"
        label = "PHISH" if expected_phishing else "LEGIT"
        print(f"  [{status}] {domain:45s} score={prob:.3f} expected={label}")

    print(f"\n  Accuracy: {correct}/{len(test_domains)} ({100*correct/len(test_domains):.0f}%)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", help="Path to CSV data file")
    parser.add_argument("--model", default="both", choices=["logistic", "gbm", "both"])
    args = parser.parse_args()

    # Generate or load data
    if args.data and os.path.exists(args.data):
        print(f"Loading data from {args.data}...")
        domains, labels = load_csv_data(args.data)
    else:
        print("Generating synthetic dataset...")
        dataset = generate_dataset(n_phishing_per_pattern=1500, n_legitimate=7000)
        domains = [d for d, _ in dataset]
        labels = [l for _, l in dataset]

        # Save for reproducibility
        os.makedirs("ml/data", exist_ok=True)
        with open("ml/data/synthetic_domains.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "label"])
            for d, l in dataset:
                writer.writerow([d, l])
        print(f"Saved dataset to ml/data/synthetic_domains.csv")

    print(f"\nDataset: {len(domains)} domains")
    print(f"  Phishing: {sum(labels)}")
    print(f"  Legitimate: {len(labels) - sum(labels)}")

    # Extract features
    print("\nExtracting features...")
    X = extract_feature_matrix(domains)
    y = np.array(labels)
    print(f"  Feature matrix: {X.shape}")

    # Train models
    models = {}
    if args.model in ("logistic", "both"):
        models["logistic"] = train_and_evaluate(X, y, "logistic")
        export_model(models["logistic"], "logistic")

    if args.model in ("gbm", "both"):
        models["gbm"] = train_and_evaluate(X, y, "gbm")
        export_model(models["gbm"], "gbm")

    # Spot-check
    best_model = models.get("gbm") or models.get("logistic")
    test_specific_domains(best_model)


if __name__ == "__main__":
    main()
