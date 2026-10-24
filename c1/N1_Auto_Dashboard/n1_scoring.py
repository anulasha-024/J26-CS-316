"""N1 Viva-1 deterministic policy exposure index, NOT a calibrated Cox risk score.

All evidence is obtained from the current physical scan or genuine saved scan.
Never treats unobserved security controls as safe, or records new NFC writes.
This deliberately does not use attacks.csv for weights or claim T2 exploits.
"""
from __future__ import annotations
import re

METHOD = "VIVA1_POLICY_INDEX_V1"
_DEFAULT_CLASSIC_KEYS = {
    "FFFFFFFFFFFF", "000000000000", "A0A1A2A3A4A5", "B0B1B2B3B4B5",
    "D3F7D3F7D3F7", "AABBCCDDEEFF",
}
_BLOCK_RE = re.compile(r"^\s*Block\s+(\d{1,2}):\s*((?:[0-9a-fA-F]{2}\s*){16})\s*$", re.I | re.M)
_KEY_RE = re.compile(r"^\s*Key\s+([AB])\s+sector\s+(\d{1,2}):\s*((?:[0-9a-fA-F]{2}\s*){6})\s*$", re.I | re.M)


def _detail(label, pts, observed, note):
    return {"factor": label, "points": pts, "observed": observed, "explanation": note}


def _unknown(family, kind, why):
    return {
        "status": "INSUFFICIENT_EVIDENCE", "score": None, "band": "UNKNOWN",
        "method": METHOD, "calibrated": False, "tier": "T2 CONTEXT ONLY",
        "scope": family, "source_kind": kind, "reasons": [],
        "coverage": why, "note": "No number is issued when necessary security evidence is missing.",
    }


def _result(family, kind, reasons, coverage, limitation):
    score = max(0, min(100, sum(x["points"] for x in reasons)))
    return {
        "status": "PROVISIONAL_SCORE", "score": score,
        "band": "LOW" if score < 35 else "MEDIUM" if score < 70 else "HIGH",
        "method": METHOD, "calibrated": False, "tier": "T2 CONTEXT ONLY",
        "scope": family, "source_kind": kind, "reasons": reasons,
        "coverage": coverage,
        "note": "Heuristic exposure index, NOT breach probability, a successful exploit, or Cox-calibrated risk. " + limitation,
    }


def _ntag215(card, kind):
    pages = card.get("_pages", {}) or {}
    required = {2, 3, 130, 131, 132}
    missing = sorted(required.difference(pages))
    if missing:
        return _unknown("NTAG215", kind, "Missing NTAG215 configuration page(s): " + ", ".join(map(str, missing)))
    if any(not isinstance(pages[p], bytes) or len(pages[p]) != 4 for p in required):
        return _unknown("NTAG215", kind, "Configuration pages are incomplete")

    auth0 = pages[131][3]
    access = pages[132][0]
    prot = bool(access & 0x80)
    cc = pages[3]
    # CC must be a known, interpretable NDEF Capability Container.
    if cc[0] != 0xE1 or (cc[3] & 0x0F) not in (0, 0x0F):
        return _unknown("NTAG215", kind, "Capability Container missing or access semantics uncertain")
    cc_write = (cc[3] & 0x0F) == 0
    static_locked = any(pages[2][2:4])
    dynamic_locked = any(pages[130][:3])
    no_lock_bits = not static_locked and not dynamic_locked

    # NTAG user NDEF starts at page 4. AUTH0 above 4 leaves at least page 4
    # outside password-guarded write range; do NOT claim the entire tag writable.
    ndef_page4_unprotected_by_pwd = auth0 > 4
    reasons = []
    if ndef_page4_unprotected_by_pwd:
        reasons.append(_detail(
            "NDEF page 4 not password guarded", 55, f"AUTH0={auth0:02X}, PROT={int(prot)}",
            "Password authentication is not enforced for writes to NDEF page 4; other restrictions may still apply."))
    else:
        reasons.append(_detail(
            "Password-based NTAG21x write access", 10, f"AUTH0={auth0:02X}, PROT={int(prot)}",
            "Configured threshold covers page 4, but a 32-bit tag password is not strong cryptographic authentication; actual enforcement has not been write-tested."))

    if no_lock_bits:
        reasons.append(_detail(
            "No permanent lock bits observed", 25 if ndef_page4_unprotected_by_pwd else 5,
            "Static/dynamic lock bytes are zero",
            "No irreversible user-page locks are observed; password/access restrictions are assessed separately."))
    else:
        reasons.append(_detail(
            "Some lock bits set", 0,
            f"Static={int(static_locked)}, Dynamic={int(dynamic_locked)}",
            "Specific protected pages are not inferred solely from presence of lock bits."))

    reasons.append(_detail(
        "CC advertises NDEF writing", 20 if (cc_write and ndef_page4_unprotected_by_pwd) else 0,
        f"CC access byte={cc[3]:02X}",
        "Capability Container advertises NDEF write access; it is advisory and is not proof an unauthorized write succeeds." if cc_write
        else "Capability Container advertises read-only; actual permanent lock enforcement not verified."))

    return _result(
        "NTAG215", kind, reasons,
        "5/5 required config pages present; AUTH0, ACCESS, static and dynamic locks, CC checked",
        "UID cloning, password secrecy, signature authenticity and exploit success are NOT verified.")


def _classic(card, raw, kind):
    # Card type alone never proves usable keys. Require a recorded sector key
    # and its associated readable block in the same genuine Flipper snapshot.
    block_indices = {int(m.group(1)) for m in _BLOCK_RE.finditer(raw) if int(m.group(1)) < 64}
    verified_sectors = {b // 4 for b in block_indices}
    observed_keys = {}
    for m in _KEY_RE.finditer(raw):
        slot, sec = m.group(1).upper(), int(m.group(2))
        candidate = "".join(m.group(3).split()).upper()
        if sec in verified_sectors and sec < 16:
            observed_keys[(slot, sec)] = candidate

    if not block_indices or not observed_keys:
        return _unknown("MIFARE Classic 1K", kind,
                        "Readable sector blocks and a corresponding recorded sector key are required")

    default_slots = sorted((slot, sec) for (slot, sec), key in observed_keys.items()
                           if key in _DEFAULT_CLASSIC_KEYS)
    reasons = [
        _detail("Legacy CRYPTO1 family", 35, "MIFARE Classic 1K",
                "Known family-level cryptographic limitations; this is NOT proof of a successful compromise."),
        _detail("Default-format sector key evidence", 45 if default_slots else 0,
                f"{len(default_slots)} default key entries in readable sectors; {len(observed_keys)} key entries examined",
                "Default key values in captured sector-key slots are an exposure signal; unobserved sector keys stay unknown."),
        _detail("Multiple default sector keys", 20 if len(default_slots) >= 8 else 0,
                f"{len(default_slots)} captured default key slots",
                "Repeated default credentials raise potential unauthorized sector access exposure."),
    ]
    return _result("MIFARE Classic 1K", kind, reasons,
                   f"{len(block_indices)}/64 block entries; {len(observed_keys)} key entries in readable sectors",
                   "Unreadable sectors and unobserved keys are UNKNOWN; do not claim full-card compromise.")


def score_card(card, raw_text, kind="FILE REPLAY"):
    """Calculate a transparent pilot index ONLY when enough scan evidence exists."""
    if not card:
        return None
    dtype = (card.get("device_type") or "").lower()
    if "ntag215" in dtype or ("ntag" in dtype and card.get("pages_total") == 135):
        return _ntag215(card, kind)
    if "mifare classic" in dtype and ("1k" in dtype or "1 k" in dtype):
        return _classic(card, raw_text or "", kind)
    return _unknown(card.get("device_type", "Unsupported card"), kind,
                    "No reviewed pilot scoring rules for this tag family")
