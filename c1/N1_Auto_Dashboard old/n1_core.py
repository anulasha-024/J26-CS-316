"""Read-only Flipper .nfc parser and N1 evidence summaries. Standard library only."""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from collections import Counter
import csv
import hashlib
import re

PAGE_RE = re.compile(r"^Page\s+(\d+)\s*:\s*((?:[0-9A-Fa-f]{2}\s*){4})\s*$", re.I)
HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[\s:]*)+$")
URI_PREFIX = {0x00: "", 0x01: "http://www.", 0x02: "https://www.", 0x03: "http://", 0x04: "https://", 0x05: "tel:", 0x06: "mailto:"}


def _clean_hex(value):
    if not value or not HEX_RE.fullmatch(value.strip()):
        return None
    return bytes.fromhex(value.replace(":", " "))


def decode_ndef(pages):
    """Decode straightforward NDEF text/URI records from NTAG user pages; otherwise return empty."""
    if not all(p in pages for p in range(4, 8)):
        return []
    buf = b"".join(pages[p] for p in sorted(pages) if 4 <= p <= 129)
    idx = 0
    while idx < len(buf):
        tag = buf[idx]
        idx += 1
        if tag == 0x00:
            continue
        if tag == 0xFE:
            break
        if idx >= len(buf):
            break
        length = buf[idx]
        idx += 1
        if length == 0xFF:
            if idx + 2 > len(buf):
                break
            length = int.from_bytes(buf[idx:idx+2], "big")
            idx += 2
        if idx + length > len(buf):
            break
        tlv = buf[idx:idx+length]
        idx += length
        if tag == 0x03:
            return _decode_ndef_records(tlv)
    return []


def _decode_ndef_records(buf):
    out = []
    off = 0
    for _ in range(24):
        if off + 3 > len(buf):
            break
        header = buf[off]
        off += 1
        short_record = bool(header & 0x10)
        id_flag = bool(header & 0x08)
        if header & 0x20:  # chunked records require additional reassembly
            break
        typelen = buf[off]
        off += 1
        payload_len_size = 1 if short_record else 4
        if off + payload_len_size > len(buf):
            break
        payloadlen = int.from_bytes(buf[off:off+payload_len_size], "big")
        off += payload_len_size
        idlen = buf[off] if id_flag and off < len(buf) else 0
        if id_flag:
            off += 1
        if off + typelen + idlen + payloadlen > len(buf):
            break
        typ = buf[off:off+typelen]
        off += typelen + idlen
        payload = buf[off:off+payloadlen]
        off += payloadlen
        kind, value = "Other NDEF record", f"{payloadlen} bytes"
        if (header & 7) == 1 and typ == b"T" and len(payload) >= 1:
            status = payload[0]
            lang_len = status & 0x3F
            encoding = "utf-16" if status & 0x80 else "utf-8"
            kind = "Text record"
            try:
                value = payload[1+lang_len:].decode(encoding, errors="replace")[:240]
            except Exception:
                value = "Undecodable text"
        elif (header & 7) == 1 and typ == b"U" and len(payload) >= 1:
            kind = "URI record"
            value = (URI_PREFIX.get(payload[0], "") + payload[1:].decode("utf-8", "replace"))[:240]
        out.append({"type": kind, "value": value})
        if header & 0x40:
            break
    return out


def parse_nfc_text(text, source=""):
    if not isinstance(text, str) or len(text) > 1_500_000:
        raise ValueError("Input file is not a supported text NFC snapshot")
    meta = {}
    pages = {}
    for line in text.splitlines():
        m = PAGE_RE.match(line.strip())
        if m:
            page = int(m.group(1))
            if page < 1024:
                pages[page] = bytes.fromhex(m.group(2))
            continue
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().lower()
            if key in {"filetype", "device type", "uid", "atqa", "sak", "pages total", "pages read", "version"}:
                meta[key] = val.strip()
    if not meta.get("device type") and not meta.get("uid"):
        raise ValueError("Not a recognized Flipper NFC file (missing device type/UID)")
    if meta.get("filetype") and "flipper nfc" not in meta["filetype"].lower():
        raise ValueError("Unsupported NFC filetype")
    uidbytes = _clean_hex(meta.get("uid"))
    uid = " ".join(f"{b:02X}" for b in uidbytes) if uidbytes else "Not available"
    device_type = meta.get("device type", "Unknown")
    is_ntag = "ntag" in device_type.lower()
    factors = {
        "UID writable": {"value": "Unverified", "detail": "UID bytes do not prove writability", "state": "unknown"},
        "Authentication": {"value": "Unknown", "detail": "Requires configuration evidence", "state": "unknown"},
        "Default key": {"value": "Not applicable" if is_ntag else "Unknown", "detail": "NTAG21x uses password protection rather than MIFARE Classic sector keys" if is_ntag else "No key test performed", "state": "neutral" if is_ntag else "unknown"},
        "Lock state": {"value": "Unknown", "detail": "Requires lock/config memory pages", "state": "unknown"},
        "NDEF protection": {"value": "Unknown", "detail": "Requires readable capability container", "state": "unknown"},
        "Known vulnerability": {"value": "Not assessed", "detail": "Never inferred solely from card type", "state": "unknown"},
    }
    if is_ntag:
        if 3 in pages:
            cc = pages[3]
            if cc[0] == 0xE1 and cc[3] == 0x00:
                factors["NDEF protection"] = {"value": "CC: write allowed", "detail": "CC access byte reports no write restriction; tag configuration must also be considered", "state": "warning"}
            elif cc[0] == 0xE1 and (cc[3] & 0x0F) == 0x0F:
                factors["NDEF protection"] = {"value": "CC: read-only", "detail": "Based on capability container access bits", "state": "ok"}
        if 2 in pages:
            static = pages[2][2:4]
            # NTAG215 dynamic lock bits: page 130; skip when not fully captured.
            dyn = pages.get(130)
            if dyn is not None:
                locked = any(static) or any(dyn[:3])
                factors["Lock state"] = {"value": "Lock bits set" if locked else "No lock bits observed", "detail": "Inspected NTAG static lock bytes and dynamic lock region", "state": "ok" if locked else "warning"}
            elif any(static):
                factors["Lock state"] = {"value": "Static lock bits set", "detail": "Dynamic lock page not available", "state": "ok"}
        # Config page addresses only for NTAG215; do not apply to NTAG213/216.
        if "ntag215" in device_type.lower() and 131 in pages:
            auth0 = pages[131][3]
            factors["Authentication"] = {"value": "AUTH0 disabled" if auth0 == 255 else f"Protection starts page {auth0}", "detail": "Derived from NTAG215 configuration page 131 AUTH0 byte; does not authenticate a password", "state": "warning" if auth0 == 255 else "ok"}
    digest = hashlib.sha256(b"".join(p.to_bytes(2,"big") + pages[p] for p in sorted(pages))).hexdigest() if pages else None
    return {
        "device_type": device_type, "uid": uid, "uid_length": len(uidbytes) if uidbytes else None,
        "atqa": meta.get("atqa", "Not available"), "sak": meta.get("sak", "Not available"),
        "pages_total": int(meta["pages total"]) if meta.get("pages total", "").isdigit() else None,
        "pages_read": int(meta["pages read"]) if meta.get("pages read", "").isdigit() else len(pages),
        "pages_observed": len(pages), "page_digest": digest, "ndef": decode_ndef(pages) if is_ntag else [],
        "factors": factors, "source": source, "received_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "_pages": pages,
    }


def public_card(card):
    return {k: v for k, v in card.items() if not k.startswith("_")}


def baseline_compare(card, project_root):
    path = project_root / "python" / "raw_data" / "NTAG215_01_BASELINE.nfc"
    if not path.exists():
        return {"status": "No baseline", "detail": "Baseline file not found"}
    try:
        baseline = parse_nfc_text(path.read_text(encoding="utf-8-sig", errors="replace"))
        if baseline["uid"] != card["uid"]:
            return {"status": "Different UID", "detail": "Captured UID does not match saved NTAG215 baseline; do not interpret as modified content"}
        a, b = baseline["_pages"], card["_pages"]
        common = sorted(set(a) & set(b))
        if not common:
            return {"status": "Insufficient pages", "detail": "Cannot compare memory from these captures"}
        changed = [p for p in common if a[p] != b[p]]
        missing = sorted(set(a) - set(b))
        if changed:
            return {"status": "Differences observed", "detail": f"{len(changed)} differing page(s) within {len(common)} comparable pages", "changed_pages": changed[:24], "missing_pages": len(missing)}
        if missing:
            return {"status": "Partial match", "detail": f"No differences across {len(common)} comparable pages; {len(missing)} baseline pages unavailable"}
        return {"status": "Page match", "detail": f"All {len(common)} available baseline pages match; this is not an authentication result"}
    except Exception as exc:
        return {"status": "Baseline unavailable", "detail": str(exc)[:130]}


def dataset_status(root):
    config_path = root / "Datasets" / "configs.csv"
    attack_path = root / "Datasets" / "attacks.csv"
    summary = {"total": 0, "complete": 0, "events": 0, "censored": 0, "configs": 0, "tiers": 0, "configuration_rows": 0, "notes": [], "recent": []}
    try:
        with config_path.open(encoding="utf-8-sig", newline="") as f:
            configs = list(csv.DictReader(f))
        summary["configuration_rows"] = len(configs)
    except OSError:
        summary["notes"].append("configs.csv not found")
    try:
        with attack_path.open(encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
    except OSError:
        rows = []
        summary["notes"].append("attacks.csv not found")
    summary["total"] = len(rows)
    valid = []
    for r in rows:
        try:
            event = float(r.get("compromised", ""))
            censored = float(r.get("censored", ""))
            duration = float(r.get("time_to_compromise", ""))
            if (event, censored) not in [(1.0, 0.0), (0.0, 1.0)] or not (duration > 0):
                continue
            valid.append(r)
        except (ValueError, TypeError):
            continue
    summary["complete"] = len(valid)
    summary["events"] = sum(float(r["compromised"]) == 1 for r in valid)
    summary["censored"] = sum(float(r["censored"]) == 1 for r in valid)
    summary["configs"] = len({r.get("config_id", "") for r in valid if r.get("config_id")})
    summary["tiers"] = len({r.get("tier", "") for r in valid if r.get("tier")})
    summary["recent"] = [{"tier": r.get("tier", "?"), "repeat": r.get("repeat_no", "?"), "time": r.get("time_to_compromise", "?"), "outcome": "Event" if r.get("compromised") in ("1", "1.0") else "Censored"} for r in valid[-5:][::-1]]
    if not summary["censored"]:
        summary["notes"].append("No complete censored observations")
    if summary["configs"] < 2:
        summary["notes"].append("Only one or zero experimentally complete configurations")
    # Even two configurations are not enough by themselves to guarantee fit.
    summary["notes"].append("Cox factor variation and sample adequacy still need validation")
    return summary
