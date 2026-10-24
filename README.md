# NFC Card and Tag Security Enhancement Framework

Using Hybrid Detection · J26-CS-316 · SLIIT Cyber Security Research

The project uses four component folders. Each member keeps their implementation files directly inside their own folder.

| Folder | Component | Owner | Proposal |
|---|---|---|---|
| [C1](c1/) | NFC Security Profile Scoring Model | Anjana I.K.D. (IT23160620) | [Report](c1/C1_IT23160620.pdf) |
| [C2](c2/) | Multi-Session Protocol-Response Provenance Fingerprinting | Anulasha K.A. (IT23139480) | [Report](c2/C2_IT23139480.pdf) |
| [C3](c3/) | NFC Tag Data Integrity Verification | Abeykoon A.M.A.S.K. (IT23403642) | [Report](c3/C3_IT23403642.pdf) |
| [C4](c4/) | NFC Hybrid Behavioural Anomaly Detection | Perera L.M.D. (IT23404182) | [Report](c4/C4_IT23404182.pdf) |

## Working on a component

1. Clone this repository and open the whole `J26-CS-316` folder in VS Code.
2. Create or select your component working branch: `c1`, `c2`, `c3`, or `c4`.
3. Put your existing implementation files directly in the matching folder. For example, C2 scripts belong in `c2/`.
4. Add a component-level `requirements.txt` when dependencies are known. Record the Python version and commands in that component's README.
5. Commit and push your changes, then open a pull request into `main`.

There is no required `src/`, `config/`, or `components/` hierarchy. Each member can keep the simple file layout used by their implementation.

## Current contents

The repository contains component documentation and the four proposal reports. A runnable application and validated model results are added by the component owners as implementation proceeds. Code that exists only on a member's computer must be copied into the matching component folder and committed before it becomes available here.

## Integration

Each component should document its inputs, outputs, dependencies, and execution steps. When components are connected, result records should identify the input scan or session, component, implementation or model version, outcome, and supporting evidence. Confidence values should be included only when actually computed and validated.

## Local data

Commit small sanitized examples and source code. Keep full raw captures, secret keys, private card dumps, protected baselines, and generated model artifacts outside Git. Optional component-local `data/`, `models/`, `results/`, and `private/` folders are ignored.
