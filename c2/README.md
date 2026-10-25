# C2 - Multi-Session Protocol-Response Provenance Fingerprinting

Owner: Anulasha K.A. · IT23139480

Session-level protocol and reader-side timing features for provenance classification, grouped evaluation, and validated UNKNOWN rejection.

[Proposal report](C2_IT23139480.pdf)

## Code

Keep this component's implementation files directly in this folder. Copy existing local code here using its current filenames. A separate `src/` folder is not required.

When working code is added, document its inputs, outputs, Python version, dependencies, execution commands, and validation results here. Add a local `requirements.txt` containing the packages this component actually uses.

Work on branch `c2` and submit a pull request into `main`.

## First Flipper Zero pilot

Use the collected Genuine/Clone CSV observations to validate source and session identifiers, build per-command session features, create physical-source-separated splits, train family-specific models, and evaluate held-out sources. Training and prediction must share the same feature extraction code. Emulator measurements and multi-day validation are separate later experiments.

### Dataset validation

Coding style for this component: use descriptive names, ordinary loops and
conditions, and functions with one clear responsibility. Add short comments
explaining the research reason for a check. Prefer readable steps to compact
Python shortcuts. Explain any necessary library operations as they are added.

### Understanding the first two files

`config.py` stores settings: the CSV location, report location, required columns,
allowed classes, commands and collection assumptions. Keeping these together
makes them easy to find and review.

`preprocessing.py` validates the observations and writes a report. Read its
functions in this order:

1. `main()` chooses paths and saves the report.
2. `validate_csv()` controls the validation steps.
3. `read_csv()` reads the file. Each observation becomes a dictionary, so
   `row["status"]` means the status value for that observation.
4. `check_columns()` checks that the expected fields exist.
5. `check_records()` groups observations and calls the specific checks.
6. `finish_report()` chooses PASS, PASS_WITH_WARNINGS or FAIL.

The specific checks have research purposes. `check_measurements()` checks numeric
values and timing arithmetic. `check_source_labels()` checks that a physical card
has consistent labels. `check_session_schedule()` checks the expected repeated
commands. `check_response()` flags incomplete hexadecimal responses for review.
`check_collection_coverage()` describes limitations in repeated sessions and days.

Useful Python concepts to study alongside these files: variables, lists,
dictionaries, sets, `if`, `for`, functions, imports, file handling and `try/except`.
Sets store distinct values, so they help detect repeated observations. A report
dictionary is written as JSON, a text format that preserves named fields.
The SHA-256 value identifies the input file version; it is not a clone-detection
feature or a separate tag-integrity component.

The panel explanation is: raw command observations are checked first, and any
inconsistencies are recorded with examples. Session fingerprints and machine
learning follow after data issues are reviewed. These scripts do not yet clean
the dataset automatically, extract fingerprints or train a model.

### Running validation

The first implementation consists of `config.py` and `preprocessing.py`. It uses
only the Python standard library (Python 3.10 or later). Model training has not
been implemented by these scripts.

Place the original CSV at `data/raw/RF_Data_Set.csv`. From this `c2` folder run:

```powershell
python preprocessing.py
```

The script writes `results/data_validation.json`, including the input SHA-256,
observed counts, errors, warnings and CSV line references. It does not modify the
raw observations or create training features. For another input or report path:

```powershell
python preprocessing.py --input "path/to/observations.csv" --report "results/review.json"
```

`FAIL` (exit code 2) means errors require review before feature generation.
`PASS_WITH_WARNINGS` (exit code 0) still requires interpretation of the warnings;
it is not proof of label accuracy, physical-card independence or research
readiness. Exit code 1 indicates a report-writing failure.

The current validation rules assume the A2 PILOT acquisition tier, software
transaction latency in microseconds and 50 trials of both family commands per
source/session. Review these assumptions against the logger protocol before
changing the configuration. Timestamp diagnostics assume Unix seconds and the
Asia/Colombo UTC+05:30 offset; the acquisition clock remains unverified.

Check flagged source IDs against original collection records. Do not guess a
replacement ID or discard rows solely to obtain a passing report. Response
markers, placeholders and unavailable responses require command-specific
interpretation before feature extraction. UID, source/run/session identifiers
and collection metadata remain traceability fields, not primary model features.
