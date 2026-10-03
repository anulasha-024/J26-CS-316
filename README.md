<div align="center">

# NFC Card and Tag Security Enhancement Framework
### Using Hybrid Detection

**J26-CS-316 · Final Year Research Project · SLIIT**

Security profiling · Provenance fingerprinting · Integrity verification · Behavioural anomaly detection

**Status: Initial development and repository setup**

</div>

---

## Project Overview

This research project investigates four complementary approaches to assessing the security of NFC cards and tags. It combines security profile scoring, protocol-response provenance fingerprinting, data integrity verification, and behavioural anomaly detection within a shared framework.

Each component addresses a separate research question. The planned framework will collect evidence through supported NFC readers, produce independent component results, and present those results through a unified dashboard.

> This repository is being established for implementation and experimentation. The architecture and features below describe the proposed system; they are not claims of completed functionality or validated detection accuracy.

## Research Problem

Reading a card's UID or stored data does not provide a complete assessment of its security. A card may have weak protection settings, a copied identity, modified contents, or unusual usage patterns. A single check cannot resolve all of these issues.

The project therefore examines four distinct questions:

1. **C1:** How exposed is the card under different attacker capabilities?
2. **C2:** Does its protocol-response behaviour resemble an original, clone, or emulator?
3. **C3:** Has its enrolled data or supported security state changed, and where?
4. **C4:** Does its usage behaviour contain suspicious or previously unseen patterns?

## Research Components

| Component | Research focus | Planned approach | Planned output |
|---|---|---|---|
| **C1 — Security Profile Scoring** | Assess card security exposure | Capability-aware profiling and calibration using laboratory outcomes, including time-to-compromise analysis | A 0–100 security risk score, risk category, and supporting factors |
| **C2 — Provenance Fingerprinting** | Distinguish source behaviour across independent sessions | Protocol-response and reader-side timing features; comparison of Random Forest, SVM, and k-NN; rejection of unsupported evidence | Original-like, clone-like, emulator-like, or UNKNOWN verdict with supporting evidence |
| **C3 — Data Integrity Verification** | Detect and localize changes relative to an enrolled baseline | HMAC-protected baseline; application/NDEF, raw-memory, and supported security-state verification; integrity journal | Verification result, affected fields or memory regions, and change evidence |
| **C4 — Behavioural Anomaly Detection** | Identify unusual NFC usage events | NFC-specific rules combined with Isolation Forest | Anomaly risk score, alert level, and explanation |

**Interpretation:** C1 measures security exposure; C2 evaluates provenance-related behaviour; C3 checks integrity; C4 assesses usage anomalies. Their outputs represent different kinds of evidence and should not be treated as interchangeable scores or definitive proof of malicious activity.

## Proposed Architecture

| Layer | Responsibility |
|---|---|
| **Shared acquisition** | Collect supported card, protocol, session, and event evidence using reader-specific adapters |
| **Independent components** | Run C1–C4 processing with separate configurations and evaluation methods |
| **Shared backend** | Store versioned component results and relevant evidence references |
| **Unified dashboard** | Present individual findings, limitations, and evidence for review |

Integration is planned around agreed data schemas and versioned result records. Reader capabilities, card family, session conditions, and unavailable measurements must remain explicit.

## Team and Responsibilities

| Member | Student ID | Component | Working branch |
|---|---|---|---|
| Anjana I.K.D. | IT23160620 | C1 — Security Profile Scoring | `c1` |
| Anulasha K.A. | IT23139480 | C2 — Provenance Fingerprinting | `c2` |
| Abeykoon A.M.A.S.K. | IT23403642 | C3 — Data Integrity Verification | `c3` |
| Perera L.M.D. | IT23404182 | C4 — Behavioural Anomaly Detection | `c4` |

Shared acquisition, interface definitions, backend integration, dashboard development, and integration testing are coordinated group responsibilities.

## Planned Repository Structure

The following folders are the agreed starting structure and will be populated during development.

```text
J26-CS-316/
    README.md
    .gitignore
    .env.example
    requirements.txt
    components/
        c1_security_scoring/
        c2_provenance/
        c3_integrity/
        c4_anomaly_detection/
    shared/
        acquisition/
            proxmark3/
            flipper_zero/
            smartphone/
        schemas/
        utils/
    backend/
    dashboard/
    docs/
        proposals/
    data/
        samples/
        raw/
        processed/
        splits/
    models/
        c1/
        c2/
        c4/
    results/
        c1/
        c2/
        c3/
        c4/
    tests/
        integration/
    scripts/
        setup/
        run/
```

| Folder | Contents |
|---|---|
| `components/` | Component source code, configuration, notebooks where needed, and component tests |
| `shared/` | Reader adapters, common utilities, and agreed input/output schemas |
| `backend/` | Shared result storage and service interfaces |
| `dashboard/` | Unified review interface |
| `docs/` | Proposals, architecture, setup instructions, protocols, and data definitions |
| `data/` | Small shareable examples and local dataset organization |
| `models/` | Model documentation and approved model artifacts |
| `results/` | Evaluation summaries, figures, and reproducibility records |
| `tests/` | Cross-component integration checks |
| `scripts/` | Setup and execution utilities |

## Development Workflow — GitHub Desktop

- **`main`** holds reviewed work and the integrated project.
- **`c1`, `c2`, `c3`, and `c4`** are component working branches created from `main`.
- Every branch starts with the same repository structure. Branches are Git versions, not separate folders.
- Members select their component branch in GitHub Desktop before editing, then commit and push their changes.
- Integration uses a pull request targeting `main`. The request should explain the change, any shared-interface changes, and the validation performed.
- After shared work is merged, members update their working branches from `main` before continuing.

Each component README should document its purpose, required inputs, output format, dependencies, execution steps, and evaluation procedure.

## Hardware and Software Plan

| Resource | Intended role |
|---|---|
| Proxmark3 RDV2 | Research-reader acquisition and supported protocol/timing experiments |
| Flipper Zero | Supported NFC reading, preliminary acquisition experiments, and authorized emulation |
| NFC-enabled smartphone | Supported profile observations and capability-tier experiments |
| Project-owned NFC cards and tags | Controlled experiments with documented card families and configurations |
| Python, pandas, NumPy, scikit-learn | Data processing, modelling, and evaluation |
| Jupyter notebooks | Exploratory analysis and experiment documentation |
| GitHub and GitHub Desktop | Collaboration, version history, and review |

Backend and dashboard implementation choices will be documented when selected. Reader-specific capabilities must be validated before using measurements as research evidence.

## Evaluation and Reproducibility

- **C1:** Evaluate calibration against laboratory outcomes and attacker capability tiers.
- **C2:** Separate physical sources and sessions appropriately between training and evaluation; report clone discrimination, false acceptance, UNKNOWN behaviour, and emulator results separately.
- **C3:** Evaluate change detection, tamper localization, journal verification, and behaviour when evidence is unavailable.
- **C4:** Evaluate rules, Isolation Forest, and their combination using precision, recall, F1, false-positive rate, and unseen-anomaly experiments.

Experimental records should identify card family, source ID, session ID, reader and firmware version, acquisition settings, dataset version, and evaluation split. Report measured results with their limitations; do not present example dashboard values as experimental findings.

## Current Status and Next Milestones

| Item | Status |
|---|---|
| Four component proposal reports | Available |
| GitHub repository | Created |
| Shared folder structure and component branches | Being established |
| C2 preliminary Flipper Zero feasibility work | Planned before Proxmark3 acquisition |
| Proxmark3 RDV2 | Awaiting delivery |
| Component implementation, training, and evaluation | Upcoming |
| Backend and unified dashboard integration | Planned |

Update this table as work is completed and link measured results from the relevant component documentation.

## Data Handling and Research Scope

Experiments are limited to project-owned or explicitly authorized cards and laboratory equipment. The framework is a research prototype and is not approved for production access-control decisions.

Commit small sanitized examples and documentation. Keep secret keys, credentials, private card dumps, protected integrity baselines, and sensitive raw captures outside the repository. Large datasets and generated artifacts should use an appropriate external storage location, with versions and retrieval instructions documented when shareable.

## Guide for Supervisors and Reviewers

1. Review the component overview and team responsibility table above.
2. Read proposal reports in `docs/proposals/` once added.
3. Inspect the relevant component README and working branch for implementation progress.
4. Review shared schemas and integration decisions in `shared/` and `docs/`.
5. Review evaluation summaries in `results/` as experiments become available.

---

**J26-CS-316 · NFC Card and Tag Security Enhancement Framework Using Hybrid Detection**
