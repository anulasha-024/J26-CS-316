# C2 — Multi-Session Protocol-Response Provenance Fingerprinting

Owner: Anulasha K.A. · IT23139480

Session-level protocol and reader-side timing features for provenance classification, grouped evaluation, and validated UNKNOWN rejection.

[Proposal report](C2_IT23139480.pdf)

## Code

Keep this component's implementation files directly in this folder. Copy existing local code here using its current filenames. A separate `src/` folder is not required.

When working code is added, document its inputs, outputs, Python version, dependencies, execution commands, and validation results here. Add a local `requirements.txt` containing the packages this component actually uses.

Work on branch `c2` and submit a pull request into `main`.

## First Flipper Zero pilot

Use the collected Genuine/Clone CSV observations to validate source and session identifiers, build per-command session features, create physical-source-separated splits, train family-specific models, and evaluate held-out sources. Training and prediction must share the same feature extraction code. Emulator measurements and multi-day validation are separate later experiments.
