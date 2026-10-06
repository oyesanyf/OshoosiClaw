---
description: Universal Invariant - Zero Mock Code, Zero Fake Data, and Strict Production-First Architecture
trigger: always_on
---

# Production Code Only: No Mocks, No Fake Data, No Shortcuts

## 1. Absolute Invariant: Real Code & Real Security Logic Only
- Never generate mock security rules (e.g. YARA rules matching lone process names like `powershell.exe`).
- Never write tests that assert against dummy mock constants instead of executing real logic.
- Never stub out backend endpoints with hardcoded simulated responses.

## 2. Accuracy-First & Zero Lazy Path Exclusions
- Blind path exclusions are strictly forbidden as a method for silencing false positives.
- Accuracy must be achieved through:
  1. Cryptographic verification (Authenticode, Windows Security Catalog `CryptCATAdminEnumCatalogFromHash`).
  2. Full decision model evaluation (Clef Decision Engine, Bayesian voters).
  3. Invariant stability checks and behavioral corroboration.

## 3. Mandatory Decision Model Governance
- When a decision model exists, all telemetry, candidate detections, and response actions must route through the decision model pipeline.
- Raw heuristic ML anomalies on unexecuted files must never directly trigger autonomous blocks without decision model validation.
