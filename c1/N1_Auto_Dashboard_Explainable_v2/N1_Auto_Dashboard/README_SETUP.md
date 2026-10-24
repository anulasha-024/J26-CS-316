# N1 Professional NFC Dashboard (Windows / Flipper Zero)

## New in Version 2 — Explainable Security Assessment

After every authorised live USB scan or correctly labelled saved-file replay, a **Preliminary Security Assessment** panel explains observed NDEF write-access settings, lock and authentication configuration evidence, and unverified properties. It displays counts of settings to review and unknown checks; these are **not a risk score**. Recommendations are for human investigation only; the scanner remains read-only. The existing Cox-derived 0–100 score remains unavailable until the study has sufficient experimental calibration data.

The existing live connection command is unchanged: `py N1_Auto_Dashboard\n1_dashboard.py --port COM3 --open-now` (change COM3 if necessary). Stop the running server with `Ctrl+C` before replacing files and restarting.

## What it does

* A standalone localhost browser dashboard opens automatically when the **first physical USB NFC capture** is successfully received, or when a **new .nfc file** arrives in a watched folder. Later captures update the already-open page.
* Shows UID, card family, ATQA/SAK, observed pages, supported NDEF records and cautiously interpreted NTAG security indicators.
* Displays real trial counts from the existing `Datasets/attacks.csv` and current readiness blockers. **No fabricated score** is shown.
* Labels **USB LIVE** and **FILE REPLAY** differently. Saved-file replay is never misrepresented as live.
* Only performs NFC **reads**. It does not write tags, change passwords/locks, clone cards or modify existing N1 datasets.

## Install into your current project

Unzip the supplied `N1_Auto_Dashboard` folder directly INSIDE your existing `N1 Implementation` folder, next to the existing `Datasets` and `python` folders:

```
N1 Implementation/
  Datasets/
    configs.csv
    attacks.csv
  python/
    raw_data/NTAG215_01_BASELINE.nfc
  01 card Scans/
  N1_Auto_Dashboard/
    START_N1_DASHBOARD.bat
    START_REPLAY_MODE.bat
    n1_dashboard.py
    n1_core.py
    dashboard.html
    requirements.txt
    inbox/
    captures/
```

On the laptop, install Python 3 and install the one USB dependency once:

```
py -m pip install -r "N1_Auto_Dashboard\requirements.txt"
```

### Physical live scan (panel mode)

1. Connect Flipper Zero with a USB data cable, insert the microSD, and ensure the device is unlocked and idle.
2. **Close Flipper Lab's CLI, qFlipper, and any other app using the same COM port.** Only one program can own that serial port at a time.
3. Double-click **`START_N1_DASHBOARD.bat`**. Leave the small collector console open; it is waiting for a card.
4. Present your **OWN authorized NTAG215 tag** close to the Flipper's NFC antenna while the dashboard collector is scanning. **Do not press the Flipper's own NFC Read menu during this mode.**
5. Upon a successful `nfc dump` capture, the PC browser opens at `http://127.0.0.1:8765/` and shows the captured card. Present another card after removal and the page refreshes automatically.

The collector sends the **documented Flipper CLI** commands `nfc` -> `dump -f /ext/nfc/... -t 3000` -> `exit` -> `storage read /ext/nfc/...`. It also saves its own copies locally in `captures/`. It never alters the tag.

**Important:** This USB integration is designed against the officially documented Flipper CLI, but it has not been tested here on your exact firmware/device. Some firmware builds may reject the command or require a COM port supplied explicitly. A genuine live card scan is only established once a real USB capture succeeds on your PC.

### If no Flipper COM port is detected

In PowerShell, from the `N1 Implementation` project folder, run:

```
py N1_Auto_Dashboard\n1_dashboard.py --port COM5
```

Replace `COM5` with the Flipper Zero serial COM port visible in Windows Device Manager. Only the automatic port detection is bypassed; the USB scanning procedure is unchanged.

### Offline demo (Flipper unavailable)

* Double-click `START_REPLAY_MODE.bat`. Dashboard opens right away in rehearsal mode.
* To trigger a new replay, **COPY**, not move, an existing authentic saved `.nfc` into `N1_Auto_Dashboard/inbox/` while the collector is running. E.g. `NTAG215_01_BASELINE.nfc`.
* The UI labels it **SAVED FILE REPLAY**. It also observes new/changed `.nfc` files under `01 card Scans/` and `python/raw_data/` after startup.
* Existing files are not silently reprocessed at program startup, so the 'new scan' only fires upon an actual file change or new copy.

### What to say to the panel

> “My N1 system collects real NFC scan data through a read-only Flipper USB CLI session and automatically opens the local assessment console when a scan is detected. It extracts observable security indicators and combines them with recorded T2 laboratory evidence. A data-readiness gate blocks Cox-based final scoring until scientifically sufficient experimental outcomes are collected. Hardware-independent replay supports reproducibility and is always labelled distinctly from a live scan.”

## Scientific integrity / limitations

* It is incorrect to call `nfc dump` scanning time *time-to-compromise*. The dashboard labels this **scan acquisition duration** separately.
* NTAG215 `UID writable`, firmware authenticity, password correctness and known CVE exposure are **not proven** by simply reading a UID or memory dump. Unverified values remain unknown.
* The baseline view is only a **memory diagnostic**; it does not replace the N3 integrity-verification model.
* Cox regression **requires adequate event/censor outcomes and factor variation**. The final 0–100 score is intentionally withheld; demo numbers are not claimed to be real scores.
* Serial read polling can miss a quick tag presentation; hold the card still until capture completes. Access to manufacturer/password-protected pages depends on device and permissions.
* Firmware CLI behavior, Windows serial permissions and NTAG access settings can change. Verify with owned test cards before presenting.
* Running Python code and opening a localhost browser is initiated **by your PC launcher**; plugging a card into Flipper Lab alone cannot launch arbitrary PC code automatically.
* After a long rehearsal, `captures/` may contain numerous `n1_dash_*.nfc` files on the Flipper microSD. These are read-only scan snapshots, not card modifications. Back them up and clean them up manually if needed.

## Troubleshooting

- **USB reconnecting / PermissionError**: close Flipper Lab, qFlipper, VS Code serial monitor; disconnect/reconnect USB.
- **No Flipper COM port**: supply `--port COMx`. Install `pyserial`.
- **CLI incompatible**: firmware may not support the documented NFC shell. Use replay mode and report this limitation.
- **Browser does not open**: visit `http://127.0.0.1:8765/` manually; browser blocking/desktop session can prevent programmatic open.
- **Card not detected**: keep the card near the Flipper antenna through the scan polling interval; don't operate the normal NFC menu simultaneously.
- **Dataset not loaded**: verify that `N1_Auto_Dashboard` is directly under `N1 Implementation`, not buried one folder deeper.

### Tested scope

The Python parser and the HTTP dashboard can be tested without hardware using the included local unit tests. The physical USB integration is unverified on the user's device because no Flipper Zero is attached to this environment.
