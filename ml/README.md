# ml/

Lightweight phishing-domain classifier. Trains a small model (gradient-boosted trees or logistic regression) on string-only features extracted from the domain. Designed to run on-device in <1ms.

For background on the attack patterns the model targets, see [`../research/uy-latam-phishing-patterns.md`](../research/uy-latam-phishing-patterns.md). For where the model fits in the iOS pipeline, see [`../architecture.md`](../architecture.md).

## What this pipeline does

1. **Generate synthetic data** (`generate_synthetic.py`) — produces phishing/benign domain pairs based on the seven documented UY/LatAm attack patterns (typosquatting, brand-keyword stacking, reward/loyalty scam, high-risk TLDs, etc.).
2. **Extract features** (`features.py`) — string-only signals: length, entropy, brand-token presence, phishing-keyword presence, high-risk TLD, digit ratio, hyphen count, etc. No network calls, no DNS, no WHOIS.
3. **Train** (`train.py`) — fits a model with scikit-learn, prints classification metrics, exports JSON weights.
4. **Export for iOS** — the trained model is serialized as JSON and committed to `models/`. The iOS app reads it at startup (`ios/Shared/PhishingClassifier.swift`).

## Run

```bash
cd ml
python3 -m venv .venv
.venv/bin/pip install scikit-learn numpy

# Generate dataset + train
.venv/bin/python train.py

# Or use existing CSV
.venv/bin/python train.py --data ml/data/synthetic_domains.csv
```

Output:
- `ml/data/synthetic_domains.csv` — generated dataset
- `models/phishing_classifier_gbm.json` — gradient-boosted model (default, committed)
- `models/phishing_classifier_logistic.json` — logistic regression baseline (for comparison)

## Regenerating the synthetic dataset

`generate_synthetic.py` is deterministic-ish (uses Python `random` with a default seed). Edit the seed at the top of the file if you want a different sample. The brand list, phishing-word list, and high-risk TLD list must stay in sync with `features.py` and the corresponding lists in `ios/Shared/BrandRuleEngine.swift` and the backend heuristics tool — adding `puntos` in one place and not the others creates silent drift.

## Exporting weights for iOS

The trained model is serialized as plain JSON with feature names and coefficients/trees. iOS reads it from the bundled `phishing_classifier_gbm.json`. After training:

```bash
cp ml/models/phishing_classifier_gbm.json ios/TwentyFourDefend/Resources/phishing_classifier.json
```

(Verify the path in the Swift code — `ios/Shared/PhishingClassifier.swift` is the source of truth.) Then commit, rebuild the app, and verify the model still loads and produces reasonable scores on `ios/python_feature_ground_truth.json`.

## Cross-validation against iOS

`ios/python_feature_ground_truth.json` is a fixture of (domain, feature-vector) pairs generated from `features.py`. The iOS unit tests use it to assert the Swift feature extractor produces identical vectors to the Python one. Whenever you change `features.py`:

1. Run `train.py` (it regenerates the ground-truth file if wired up — otherwise regenerate manually).
2. Run iOS tests: `cd ../ios && xcodebuild test -scheme TwentyFourDefend`.
3. If the cross-validation test fails, the Swift implementation needs to be updated to match. The Swift and Python feature extractors must agree byte-for-byte on every domain.

## Known limitations

These are real and well-understood. Don't pretend they aren't:

- **Synthetic training data dominates.** The dataset is generated from documented attack patterns; real-world phishing diverges. A model trained on synthetic data over-fits to those patterns and misses novel ones. The agent on the backend is the safety net for unknown domains.
- **Digit-heavy legitimate domains.** Some legitimate domains (banks, CDNs, ad-tech) have digits in subdomains, which the digit-ratio feature penalizes. Compensate with the infrastructure allowlist in iOS, not by removing the feature.
- **Punycode / IDN.** The current pipeline assumes ASCII. Internationalized domain names are not handled. This is a backlog item in `research/improvements.md`.
- **No labels for the ambiguous middle.** "Warn but don't block" is a useful third class, but synthetic generation doesn't produce credible warn-class examples. The agent fills this gap.
- **Static export.** Updating the model requires rebuilding and shipping a new iOS version. Backlog: serve the model from a public CDN endpoint similar to the bloom filter, with versioning.

## Useful files

| File | Purpose |
|------|---------|
| `features.py` | String-only feature extractor (must match Swift) |
| `generate_synthetic.py` | Synthetic dataset generation |
| `train.py` | Training entry point |
| `models/phishing_classifier_gbm.json` | Production-shipped model |
| `models/phishing_classifier_logistic.json` | Baseline for comparison |
| `../research/uy-latam-phishing-patterns.md` | Attack-pattern documentation that drives synthesis |
| `../research/improvements.md` | Backlog (ML-related items live in their own section) |
