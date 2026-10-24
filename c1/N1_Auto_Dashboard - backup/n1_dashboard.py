"""N1 NFC Security Live Dashboard.

Read-only collector. Uses the documented Flipper CLI (`nfc` -> `dump`,
then `storage read`) when available. Also supports offline replay of genuine
Flipper .nfc snapshots dropped in inbox/. No tag writes, locks, or key tests.
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import re
import threading
import time
import webbrowser

from n1_core import baseline_compare, dataset_status, parse_nfc_text, public_card

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
INBOX = HERE / "inbox"
CAPTURES = HERE / "captures"
TEMPLATE = HERE / "dashboard.html"
PORT = 8765

for directory in (INBOX, CAPTURES):
    directory.mkdir(parents=True, exist_ok=True)


class SharedState:
    def __init__(self):
        self.lock = threading.RLock()
        self.card = None
        self.baseline = None
        self.source_kind = None
        self.scans = 0
        self.device = "USB initializing"
        self.device_detail = "Looking for Flipper Zero"
        self.last_latency = None
        self.activity = deque(maxlen=12)
        self.last_error = ""
        self.browser_opened = False
        self.url = f"http://127.0.0.1:{PORT}/"
        self.last_id = None
        self.last_card_time = None

    def event(self, message, level="info"):
        with self.lock:
            self.activity.appendleft({"time": datetime.now().strftime("%H:%M:%S"), "message": str(message)[:240], "level": level})

    def device_status(self, status, detail):
        with self.lock:
            self.device = status
            self.device_detail = detail[:190]

    def accept(self, text, source, kind, latency=None):
        card = parse_nfc_text(text, source=source)
        comparison = baseline_compare(card, PROJECT)
        with self.lock:
            self.card = public_card(card)
            self.baseline = comparison
            self.source_kind = kind
            self.scans += 1
            self.last_latency = round(latency, 2) if latency is not None else None
            self.last_id = card["uid"]
            self.last_card_time = time.monotonic()
            self.activity.appendleft({"time": datetime.now().strftime("%H:%M:%S"), "message": f"{kind}: {card['device_type']} / {card['uid']}", "level": "success"})
            needs_browser = not self.browser_opened
            if needs_browser:
                self.browser_opened = True
                url = self.url
            else:
                url = None
        if url:
            # Open exactly once at first scan. If already open, UI refreshes on its own.
            try:
                webbrowser.open(url, new=2)
            except Exception as exc:
                self.event(f"Browser could not auto-open: {exc}", "error")
        return card

    def snapshot(self):
        with self.lock:
            payload = {
                "card": self.card,
                "baseline": self.baseline,
                "kind": self.source_kind,
                "scans": self.scans,
                "device": self.device,
                "device_detail": self.device_detail,
                "last_latency": self.last_latency,
                "events": list(self.activity),
                "last_error": self.last_error,
                "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            }
        payload["dataset"] = dataset_status(PROJECT)
        return payload

STATE = SharedState()


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.respond(TEMPLATE.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self.respond(json.dumps(STATE.snapshot(), ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
        elif self.path == "/health":
            self.respond(b"ok", "text/plain; charset=utf-8")
        else:
            self.send_error(404)

    def respond(self, content, mime):
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, fmt, *args):
        # Suppress noisy UI polling logs.
        if self.path != "/api/state":
            logging.info("HTTP %s", fmt % args)


def _iter_files():
    roots = [PROJECT / "01 card Scans", PROJECT / "python" / "raw_data", INBOX]
    for root in roots:
        if root.exists():
            try:
                yield from root.rglob("*.nfc")
            except OSError:
                pass


def watch_files(stop):
    """A new/changed local .nfc file is visibly labelled FILE REPLAY, never USB LIVE."""
    known = {}
    for p in _iter_files():
        try:
            s = p.stat()
            known[str(p)] = (s.st_size, s.st_mtime_ns)
        except OSError:
            pass
    STATE.event("Offline file watcher ready; new .nfc snapshots trigger dashboard")
    while not stop.is_set():
        for p in _iter_files():
            try:
                s = p.stat()
                fingerprint = (s.st_size, s.st_mtime_ns)
                key = str(p)
                if fingerprint == known.get(key):
                    continue
                # Wait until the file is stable to avoid reading a half-copied snapshot.
                time.sleep(0.30)
                s2 = p.stat()
                if (s2.st_size, s2.st_mtime_ns) != fingerprint:
                    continue
                known[key] = fingerprint
                text = p.read_text(encoding="utf-8-sig", errors="replace")
                STATE.accept(text, str(p.relative_to(PROJECT)), "FILE REPLAY")
            except (OSError, UnicodeError, ValueError) as exc:
                STATE.event(f"Skipped file {p.name}: {str(exc)[:90]}", "warning")
        stop.wait(1.2)


def find_flipper_port(explicit=None):
    try:
        from serial.tools import list_ports
    except ImportError:
        return None, "pyserial is missing (pip install -r requirements.txt)"
    if explicit:
        return explicit, f"Using selected port {explicit}"
    ports = list(list_ports.comports())
    matches = []
    for port in ports:
        blob = " ".join(str(x or "") for x in [port.description, port.manufacturer, port.product, port.hwid]).lower()
        if "flipper" in blob:
            matches.append(port.device)
    if len(matches) == 1:
        return matches[0], f"Detected Flipper on {matches[0]}"
    if len(matches) > 1:
        return None, "Multiple Flipper ports: start launcher with --port COMx"
    return None, "No Flipper COM port identified; use --port COMx if device description is generic"


def read_output(serial_port, *, min_seconds=0.8, max_seconds=5.0, idle_seconds=0.6):
    """Read asynchronous CLI output, including scans that take several seconds."""
    started = time.monotonic()
    last_received = started
    chunks = []
    while time.monotonic() - started < max_seconds:
        chunk = serial_port.read(8192)
        if chunk:
            chunks.append(chunk)
            last_received = time.monotonic()
        if time.monotonic() - started >= min_seconds and time.monotonic() - last_received >= idle_seconds:
            break
    return b"".join(chunks).decode("utf-8", errors="replace")


def command(s, line, *, min_seconds=0.8, max_seconds=5.0):
    s.write(line.encode("ascii") + b"\r\n")
    s.flush()
    return read_output(s, min_seconds=min_seconds, max_seconds=max_seconds)


def extract_nfc_section(text):
    match = re.search(r"(?im)^\s*Filetype:\s*Flipper NFC device", text)
    if not match:
        raise ValueError("No Flipper NFC file content in storage read response")
    # End before subsequent terminal prompt lines; parse ignores irrelevant footer.
    content = text[match.start():]
    # Parse will validate that the data begins with a recognized file header.
    return content


def usb_scan_loop(stop, selected_port=None):
    last_uid = None
    empty_cycles = 0
    attempt = 0
    while not stop.is_set():
        port, reason = find_flipper_port(selected_port)
        if not port:
            STATE.device_status("Offline", reason)
            stop.wait(3.0)
            continue
        try:
            import serial
            with serial.Serial(port=port, baudrate=115200, timeout=0.13, write_timeout=3) as s:
                STATE.device_status("Connected", f"{port}: initializing read-only NFC CLI")
                read_output(s, min_seconds=0.4, max_seconds=1.1)
                command(s, "", min_seconds=0.3, max_seconds=1.3)
                while not stop.is_set():
                    attempt += 1
                    # Unique filenames prevent an unsuccessful read from reusing stale card evidence.
                    stamp = datetime.now().strftime("%H%M%S")
                    remote = f"/ext/nfc/n1_dash_{stamp}_{attempt % 10000:04d}.nfc"
                    STATE.device_status("Scanning", f"{port} — hold an owned NTAG215 near Flipper NFC antenna")
                    intro = command(s, "nfc", min_seconds=0.8, max_seconds=2.8)
                    if re.search(r"(?i)(unknown command|command not found|error.*nfc)", intro):
                        STATE.device_status("CLI unsupported", "Device firmware did not expose the documented nfc shell")
                        STATE.event("nfc CLI unavailable — FILE REPLAY still works", "warning")
                        stop.wait(15)
                        break
                    t0 = time.perf_counter()
                    dump_result = command(s, f"dump -f {remote} -t 3000", min_seconds=3.4, max_seconds=12)
                    # The documented nfc command enters a sub-shell; exit to the main shell.
                    command(s, "exit", min_seconds=0.35, max_seconds=1.7)
                    # Even if dump reports no card, reading a UNIQUE filename is safe; it won't be stale.
                    captured = command(s, f"storage read {remote}", min_seconds=0.45, max_seconds=7.5)
                    if "Filetype: Flipper NFC device" not in captured:
                        empty_cycles += 1
                        if empty_cycles >= 1:
                            last_uid = None
                        if "unknown command" in dump_result.lower():
                            STATE.device_status("CLI incompatible", "Try firmware update / manual FILE REPLAY mode")
                            STATE.event("nfc dump command rejected; manual file replay available", "warning")
                            stop.wait(15)
                            break
                        STATE.device_status("Scanning", f"{port} — ready; waiting for card")
                        continue
                    empty_cycles = 0
                    nfc_content = extract_nfc_section(captured)
                    parsed = parse_nfc_text(nfc_content, remote)
                    if parsed["uid"] == "Not available":
                        STATE.event("Scan ignored — missing UID", "warning")
                        continue
                    if parsed["uid"] != last_uid:
                        # Save immutable local evidence and label observed timing as acquisition latency.
                        filename = f"n1_usb_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{attempt:04d}.nfc"
                        (CAPTURES / filename).write_text(nfc_content, encoding="utf-8")
                        STATE.accept(nfc_content, f"captures/{filename}", "USB LIVE", time.perf_counter() - t0)
                    last_uid = parsed["uid"]
                    STATE.device_status("Scanning", f"{port} — card captured; remove then present again for next scan")
        except Exception as exc:
            msg = f"{type(exc).__name__}: {str(exc)[:145]}"
            STATE.device_status("USB reconnecting", f"{port} — {msg}")
            STATE.event(f"USB: {msg}. Close Flipper Lab/qFlipper if using this COM port.", "warning")
            stop.wait(4)


def main():
    global PORT, STATE
    p = argparse.ArgumentParser(description="N1 automatic NFC dashboard")
    p.add_argument("--port", help="Windows COM port, e.g. COM5; autodetected if omitted")
    p.add_argument("--http-port", type=int, default=8765)
    p.add_argument("--mode", choices=["auto", "replay"], default="auto")
    p.add_argument("--open-now", action="store_true", help="Open dashboard immediately for rehearsal; otherwise opens at first scan")
    args = p.parse_args()
    PORT = args.http_port
    STATE = SharedState()
    stop = threading.Event()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    server = ThreadingHTTPServer(("127.0.0.1", PORT), RequestHandler)
    threads = [threading.Thread(target=watch_files, args=(stop,), daemon=True)]
    if args.mode == "auto":
        threads.append(threading.Thread(target=usb_scan_loop, args=(stop, args.port), daemon=True))
    else:
        STATE.device_status("Replay only", "File watcher active; no USB device needed")
    for thread in threads:
        thread.start()
    print("="*65)
    print("N1 NFC SECURITY DASHBOARD  |  READ-ONLY")
    print("="*65)
    print(f"Project:    {PROJECT}")
    print(f"Dashboard:  http://127.0.0.1:{PORT}/")
    print(f"File inbox: {INBOX}")
    print(f"USB mode:   {args.mode}")
    print("Browser opens automatically on FIRST card / new .nfc file.")
    print("No card writes. No fabricated risk scores. Press Ctrl+C to stop.")
    print("="*65)
    if args.open_now:
        STATE.browser_opened = True
        webbrowser.open(STATE.url, new=2)
    try:
        server.serve_forever(poll_interval=0.35)
    except KeyboardInterrupt:
        print("\nShutting down N1 dashboard...")
    finally:
        stop.set()
        server.server_close()


if __name__ == "__main__":
    main()
