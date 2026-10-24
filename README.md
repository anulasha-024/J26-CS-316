<div align="center">

<img src="https://raw.githubusercontent.com/anulasha-024/J26-CS-316/369b9ac6c33879d0033e8c7b1fc0b7a8492b2315/docs/assets/nfc-security-banner.png" alt="NFC security research banner with a contactless smart card and protective shield" width="100%">

# NFC Card and Tag Security Enhancement Framework
### Using Hybrid Detection

**Final Year Research Project · SLIIT · Cyber Security**

<img src="https://raw.githubusercontent.com/anulasha-024/J26-CS-316/369b9ac6c33879d0033e8c7b1fc0b7a8492b2315/docs/assets/project-status.svg" alt="J26-CS-316 · Four components · SLIIT Cyber Security · Initial development" width="730">

<br>

[Overview](#project-overview) · [Components](#research-components) · [Architecture](#proposed-architecture) · [Team](#research-team) · [Progress](#project-progress) · [Get started](#getting-started) · [Proposals](#proposal-reports)

</div>

---

## Project Overview

This project investigates NFC security through four complementary assessments: **security exposure, source behaviour, data integrity, and usage patterns**.

Each member develops one component in a dedicated folder. The components retain their own methods and evaluation procedures, with a shared result format planned for integration.

| Question | Component |
|---|---|
| How exposed is the card? | **C1** assesses protection settings and attacker capabilities. |
| Does its source behaviour resemble an original, clone, or emulator? | **C2** examines protocol responses and reader-side timing evidence. |
| Has the enrolled data changed? | **C3** compares current contents with a protected baseline. |
| Is its usage unusual? | **C4** combines behavioural rules with anomaly detection. |

> **Development status:** The repository currently contains component documentation and proposal reports. The capabilities below describe the research plan. Working implementations, measured results, and execution instructions will be added by the component owners.

## Research Components

<table>
<tr>
<td width="50%" valign="top">

<h3>C1 · Security Profile Scoring</h3>
<p><strong>Assess protection and exposure.</strong></p>
<p>Capability-aware profiling, laboratory outcomes, and time-to-compromise calibration.</p>
<p><strong>Planned output:</strong> 0–100 security risk score, risk category, and contributing factors.</p>
<p><a href="c1/">Open C1</a> · <a href="c1/C1_IT23160620.pdf">Read proposal</a></p>

</td>
<td width="50%" valign="top">

<h3>C2 · Provenance Fingerprinting</h3>
<p><strong>Examine the source behind the response.</strong></p>
<p>Multi-session protocol and timing features, Random Forest/SVM/k-NN comparison, and validated UNKNOWN rejection.</p>
<p><strong>Planned output:</strong> Original-like, Clone-like, Emulator-like, or UNKNOWN, with supporting evidence.</p>
<p><a href="c2/">Open C2</a> · <a href="c2/C2_IT23139480.pdf">Read proposal</a></p>

</td>
</tr>
<tr>
<td width="50%" valign="top">

<h3>C3 · Data Integrity Verification</h3>
<p><strong>Identify changes after enrollment.</strong></p>
<p>HMAC-protected baselines, application/NDEF and raw-memory checks, supported security-state checks, and an integrity journal.</p>
<p><strong>Planned output:</strong> Integrity result, changed fields or memory regions, and tamper localization.</p>
<p><a href="c3/">Open C3</a> · <a href="c3/C3_IT23403642.pdf">Read proposal</a></p>

</td>
<td width="50%" valign="top">

<h3>C4 · Behavioural Anomaly Detection</h3>
<p><strong>Recognize unusual usage patterns.</strong></p>
<p>NFC-specific behavioural rules combined with Isolation Forest on usage-event features.</p>
<p><strong>Planned output:</strong> Anomaly risk score, alert level, and an explanation.</p>
<p><a href="c4/">Open C4</a> · <a href="c4/C4_IT23404182.pdf">Read proposal</a></p>

</td>
</tr>
</table>

C1 and C4 scores represent separate assessments. C2 findings describe observed source behaviour. C3 results describe integrity relative to an enrolled baseline. Unavailable evidence remains explicit in each component's result.

## Proposed Architecture

<p align="center">
<img src="https://raw.githubusercontent.com/anulasha-024/J26-CS-316/369b9ac6c33879d0033e8c7b1fc0b7a8492b2315/docs/assets/framework-architecture.png" alt="Proposed architecture: shared NFC acquisition feeds C1, C2, C3, and C4; a planned backend and dashboard bring their findings together" width="100%">
</p>

**Integration plan:** Reader observations feed the relevant components. Versioned result records connect their findings to the input scan or session. A backend and dashboard are planned for storage, coordination, and review.

The diagram describes the proposed system. It does not require additional code folders: implementation stays within `c1/`, `c2/`, `c3/`, and `c4/`.

## Research Team

| Member | Student ID | Responsibility | Code folder |
|---|---|---|---|
| **Anjana I.K.D.** | IT23160620 | C1 — Security Profile Scoring | [`c1/`](c1/) |
| **Anulasha K.A.** | IT23139480 | C2 — Provenance Fingerprinting | [`c2/`](c2/) |
| **Abeykoon A.M.A.S.K.** | IT23403642 | C3 — Data Integrity Verification | [`c3/`](c3/) |
| **Perera L.M.D.** | IT23404182 | C4 — Behavioural Anomaly Detection | [`c4/`](c4/) |

## Project Progress

| Item | Current position |
|---|---|
| Component proposal reports | Four reports available |
| Shared repository | Created and organized into `c1/`–`c4/` |
| C2 Flipper Zero pilot observations | Genuine/Clone data collected; coding and validation pending |
| Proxmark3 RDV2 | Awaiting delivery |
| Published implementation and evaluation | To be added by component owners |
| Integrated backend and dashboard | Planned |

Progress entries describe the current reported stage. Update them with commits, experiment records, and measured results as work is completed.

## Getting Started

**Tools:** GitHub Desktop or Git, VS Code, and Python. Each component records its own Python version and dependencies when working code is added.

1. Clone this repository and open the whole `J26-CS-316` folder in VS Code.
2. Create or select your component working branch: `c1`, `c2`, `c3`, or `c4`.
3. Add your implementation files directly inside the matching folder.
4. Record dependencies in that component's `requirements.txt`.
5. Document the inputs, outputs, run commands, and validation in its README.
6. Commit and push a focused change, then open a pull request into `main`.

| Folder | Keep here |
|---|---|
| [`c1/`](c1/) | C1 implementation, dependencies, documentation, and proposal |
| [`c2/`](c2/) | C2 processing, feature extraction, training, evaluation, prediction, and proposal |
| [`c3/`](c3/) | C3 enrollment, baseline protection, verification, integrity records, and proposal |
| [`c4/`](c4/) | C4 event processing, behavioural detection, evaluation, and proposal |

Files can sit directly inside these folders. A separate `src/` or `components/` hierarchy is not required.

<details>
<summary><strong>Evaluation and integration notes</strong></summary>

| Component | Evaluation focus |
|---|---|
| **C1** | Calibration against laboratory outcomes and attacker capability tiers |
| **C2** | Physical-source separation, held-out card performance, false acceptance, cross-session stability, UNKNOWN rejection, and separate emulator reporting |
| **C3** | Change detection, tamper localization, journal verification, and unavailable evidence |
| **C4** | Rules and model baselines, precision, recall, F1, false-positive rate, and unseen-anomaly detection |

Result records should identify the input scan/session, component, implementation or model version, outcome, and supporting evidence. Include confidence values only when actually computed and validated.

</details>

<details>
<summary><strong>Research data and local files</strong></summary>

Experiments use project-owned or explicitly authorized laboratory cards and equipment.

Commit source code, documentation, and small sanitized examples. Keep full raw captures, secret keys, private card dumps, protected baselines, and generated model artifacts outside Git. Optional component-local `data/`, `models/`, `results/`, and `private/` folders are ignored.

Code stored only on a member's computer becomes available to the team after it is added to the matching component folder and committed.

</details>

## Proposal Reports

| Component | Report |
|---|---|
| **C1** | [NFC Security Profile Scoring — IT23160620](c1/C1_IT23160620.pdf) |
| **C2** | [Provenance Fingerprinting — IT23139480](c2/C2_IT23139480.pdf) |
| **C3** | [NFC Tag Data Integrity Verification — IT23403642](c3/C3_IT23403642.pdf) |
| **C4** | [NFC Behavioural Anomaly Detection — IT23404182](c4/C4_IT23404182.pdf) |

---

<div align="center">

<strong>J26-CS-316 · SLIIT · Cyber Security Research</strong>

Four components. One NFC security research framework.

</div>
