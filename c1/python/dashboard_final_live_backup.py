from pathlib import Path
import json

import pandas as pd
import streamlit as st


# ============================================================
# N1 NFC SECURITY SCORING RESEARCH DASHBOARD
# ============================================================


# ============================================================
# PAGE SETUP
# ============================================================

st.set_page_config(
    page_title="N1 NFC Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ N1 NFC Security Scoring Research Dashboard")

st.caption(
    "Exploitability-Calibrated and Attacker-Tiered "
    "Security Scoring Model for NFC Cards and Tags"
)


# ============================================================
# FILE PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = PROJECT_ROOT / "Datasets"

CONFIGS_FILE = DATASET_DIR / "configs.csv"
ATTACKS_FILE = DATASET_DIR / "attacks.csv"
TIMING_FILE = DATASET_DIR / "automated_timing.csv"

LIVE_STATUS_FILE = (
    Path(__file__).with_name("live_card_status.json")
)


# ============================================================
# LOAD CSV
# ============================================================

def load_csv(path):

    try:

        if path.exists():
            return pd.read_csv(path)

        return pd.DataFrame()

    except Exception as error:

        st.warning(
            f"Could not read {path.name}: {error}"
        )

        return pd.DataFrame()


configs = load_csv(CONFIGS_FILE)
attacks = load_csv(ATTACKS_FILE)
timing = load_csv(TIMING_FILE)


# ============================================================
# LAB CARD SUMMARY
# ============================================================

lab_cards = pd.DataFrame(
    [
        {
            "Card ID": "NTAG215_01",
            "Family": "NTAG215",
            "UID": "04 03 72 A0 31 02 89",
            "Evidence": "Baseline + automated timing",
            "Status": "Tested",
        },
        {
            "Card ID": "NTAG215_02",
            "Family": "NTAG215",
            "UID": "04 A3 C0 90 31 02 89",
            "Evidence": "Baseline + automated timing",
            "Status": "Tested",
        },
        {
            "Card ID": "MIFARE1K_01",
            "Family": "MIFARE Classic 1K",
            "UID": "B7 95 66 5F",
            "Evidence": (
                "32/32 keys found, "
                "16/16 sectors read"
            ),
            "Status": "Baseline captured",
        },
        {
            "Card ID": "MIFARE1K_02",
            "Family": "MIFARE Classic 1K",
            "UID": "B7 22 FD 5F",
            "Evidence": (
                "32/32 keys found, "
                "16/16 sectors read"
            ),
            "Status": "Baseline captured",
        },
    ]
)


# ============================================================
# CORE SECURITY FACTORS
# ============================================================

CORE_FACTORS = [
    "uid_writable",
    "auth_type",
    "default_key_present",
    "lock_state",
    "ndef_protection",
    "cve_flag",
]


# ============================================================
# NORMALIZE VALUES
# ============================================================

def normalize_value(value):

    if pd.isna(value):
        return ""

    return str(value).strip().lower()


# ============================================================
# SECURITY FACTOR ENCODING
# ============================================================

def encode_factor(factor, value):

    value = normalize_value(value)

    if value in [
        "",
        "unknown",
        "none",
        "nan",
    ]:
        return None

    # --------------------------------------------------------
    # UID WRITABILITY
    # --------------------------------------------------------

    if factor == "uid_writable":

        if value in [
            "fixed uid",
            "not writable",
            "read only",
            "readonly",
            "no",
        ]:
            return 0.0

        if value in [
            "partially writable",
            "partial",
        ]:
            return 0.5

        if value in [
            "writable",
            "yes",
            "uid writable",
        ]:
            return 1.0

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    if factor == "auth_type":

        if value in [
            "no authentication",
            "none",
            "no auth",
        ]:
            return 1.0

        if (
            "crypto1" in value
            or
            "password" in value
            or
            "weak" in value
        ):
            # Baseline-only encoding.
            return 0.5

        if (
            "aes" in value
            or
            "strong" in value
        ):
            return 0.0

    # --------------------------------------------------------
    # DEFAULT KEYS
    # --------------------------------------------------------

    if factor == "default_key_present":

        if value in [
            "not applicable",
            "n/a",
            "na",
        ]:
            return "NA"

        if value in [
            "yes",
            "true",
            "present",
        ]:
            return 1.0

        if value in [
            "no",
            "false",
            "not present",
        ]:
            return 0.0

    # --------------------------------------------------------
    # LOCK STATE
    # --------------------------------------------------------

    if factor == "lock_state":

        if value in [
            "unlocked",
            "not locked",
        ]:
            return 1.0

        if value in [
            "partial",
            "partially locked",
        ]:
            return 0.5

        if value in [
            "locked",
            "read only",
            "readonly",
        ]:
            return 0.0

    # --------------------------------------------------------
    # NDEF PROTECTION
    # --------------------------------------------------------

    if factor == "ndef_protection":

        if value in [
            "not applicable",
            "n/a",
            "na",
        ]:
            return "NA"

        if value in [
            "unprotected",
            "none",
            "no protection",
        ]:
            return 1.0

        if (
            "partial" in value
            or
            "password" in value
        ):
            return 0.5

        if value in [
            "protected",
            "secure",
        ]:
            return 0.0

    # --------------------------------------------------------
    # CVE FLAG
    # --------------------------------------------------------

    if factor == "cve_flag":

        if value in [
            "no known cve",
            "no",
            "false",
            "none",
        ]:
            return 0.0

        if value in [
            "known cve",
            "yes",
            "true",
        ]:
            return 1.0

    return None


# ============================================================
# OBSERVED-FACTOR SCORE
# ============================================================

def calculate_observed_factor_score(row):

    risk_values = []

    applicable_count = 0
    known_count = 0

    for factor in CORE_FACTORS:

        if factor not in row.index:
            continue

        encoded = encode_factor(
            factor,
            row[factor],
        )

        if encoded == "NA":
            continue

        applicable_count += 1

        if encoded is not None:

            known_count += 1
            risk_values.append(encoded)

    if (
        applicable_count == 0
        or
        len(risk_values) == 0
    ):

        return None, 0

    coverage = round(
        known_count
        / applicable_count
        * 100
    )

    score = round(
        sum(risk_values)
        / len(risk_values)
        * 100
    )

    return score, coverage


# ============================================================
# PRELIMINARY UNWEIGHTED BASELINE SCORE
# ============================================================

def calculate_preliminary_score(row):

    score, coverage = (
        calculate_observed_factor_score(row)
    )

    if score is None:

        return None, coverage

    if coverage < 80:

        return None, coverage

    return score, coverage


# ============================================================
# BUILD SCORE TABLE
# ============================================================

score_rows = []

if not configs.empty:

    for _, row in configs.iterrows():

        observed_score, coverage = (
            calculate_observed_factor_score(row)
        )

        preliminary_score, _ = (
            calculate_preliminary_score(row)
        )

        config_id = str(
            row.get(
                "config_id",
                "UNKNOWN",
            )
        )

        card_id = str(
            row.get(
                "card_instance",
                "UNKNOWN",
            )
        )

        family = str(
            row.get(
                "family",
                "UNKNOWN",
            )
        )

        if preliminary_score is None:

            baseline_status = (
                "Pending – insufficient evidence"
            )

        else:

            baseline_status = (
                "Available – unweighted baseline"
            )

        score_rows.append(
            {
                "Config ID": config_id,
                "Card": card_id,
                "Family": family,
                "Observed-Factor Score": observed_score,
                "Evidence Coverage (%)": coverage,
                "Preliminary Baseline Score": preliminary_score,
                "Baseline Status": baseline_status,
                "Final Cox Score": "Pending",
            }
        )


score_table = pd.DataFrame(score_rows)


# ============================================================
# MISSING EVIDENCE TABLE
# ============================================================

missing_rows = []

if not configs.empty:

    for _, row in configs.iterrows():

        missing = []

        for factor in CORE_FACTORS:

            if factor not in row.index:

                missing.append(factor)
                continue

            encoded = encode_factor(
                factor,
                row[factor],
            )

            if encoded is None:

                missing.append(factor)

        card_id = str(
            row.get(
                "card_instance",
                "UNKNOWN",
            )
        )

        if len(missing) == 0:

            missing_text = "None"
            status = "Baseline evidence complete"

        else:

            missing_text = ", ".join(missing)
            status = "Evidence required"

        missing_rows.append(
            {
                "Card": card_id,
                "Missing Core Evidence": missing_text,
                "Status": status,
            }
        )


missing_table = pd.DataFrame(missing_rows)


# ============================================================
# COUNT UNKNOWN CORE VALUES
# ============================================================

unknown_core_count = 0

if not configs.empty:

    for _, row in configs.iterrows():

        for factor in CORE_FACTORS:

            if factor not in row.index:

                unknown_core_count += 1
                continue

            encoded = encode_factor(
                factor,
                row[factor],
            )

            if encoded is None:

                unknown_core_count += 1


# ============================================================
# ATTACK OUTCOME READINESS
# ============================================================

compromised_available = False
censored_available = False

if not attacks.empty:

    if "compromised" in attacks.columns:

        compromised_values = pd.to_numeric(
            attacks["compromised"],
            errors="coerce",
        )

        compromised_available = bool(
            (compromised_values == 1).any()
        )

    if "censored" in attacks.columns:

        censored_values = pd.to_numeric(
            attacks["censored"],
            errors="coerce",
        )

        censored_available = bool(
            (censored_values == 1).any()
        )


# ============================================================
# AUTOMATED TIMING SUMMARY
# ============================================================

timing_trials = 0
verified_modifications = 0
average_verified_time = None

if not timing.empty:

    timing_trials = len(timing)

    if (
        "modification_verified"
        in timing.columns
    ):

        verified_series = pd.to_numeric(
            timing["modification_verified"],
            errors="coerce",
        )

        verified_modifications = int(
            (verified_series == 1).sum()
        )

    if (
        "verified_modification_time_s"
        in timing.columns
    ):

        time_series = pd.to_numeric(
            timing[
                "verified_modification_time_s"
            ],
            errors="coerce",
        )

        valid_times = time_series.dropna()

        if len(valid_times) > 0:

            average_verified_time = (
                valid_times.mean()
            )


# ============================================================
# LIVE STATUS LOADER
# ============================================================

def load_live_status():

    try:

        if not LIVE_STATUS_FILE.exists():
            return None

        with open(
            LIVE_STATUS_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(file)

    except Exception:

        return None


# ============================================================
# LIVE NFC CARD PANEL
# ============================================================

@st.fragment(run_every="2s")
def live_card_panel():

    st.header(
        "📡 Live NFC Card Detection"
    )

    live_status = load_live_status()

    if not live_status:

        st.info(
            "No live NFC card scan is available. "
            "Run live_card_scanner.py and scan a card."
        )

        return

    status = live_status.get(
        "status",
        "UNKNOWN",
    )

    card_id = live_status.get(
        "card_id",
        "UNKNOWN",
    )

    uid = live_status.get(
        "uid",
        "UNKNOWN",
    )

    family = live_status.get(
        "family",
        "UNKNOWN",
    )

    tier = live_status.get(
        "tier",
        "T2 - Flipper Zero",
    )

    timestamp = live_status.get(
        "timestamp",
        "UNKNOWN",
    )

    known_card = live_status.get(
        "known_card",
        False,
    )

    # --------------------------------------------------------
    # STATUS MESSAGE
    # --------------------------------------------------------

    if known_card:

        st.success(
            "✅ LIVE CARD DETECTED — "
            "KNOWN LAB CARD"
        )

    else:

        st.error(
            "⚠️ LIVE CARD DETECTED — "
            "UNKNOWN CARD"
        )

    # --------------------------------------------------------
    # CARD DETAILS
    # Full text layout - no truncation
    # --------------------------------------------------------

    c1, c2 = st.columns(2)

    with c1:

        st.markdown(
            "### Card ID"
        )

        st.write(
            card_id
        )

        st.markdown(
            "### Family"
        )

        st.write(
            family
        )

    with c2:

        st.markdown(
            "### Attacker Tier"
        )

        st.write(
            tier
        )

        st.markdown(
            "### Status"
        )

        st.write(
            status
        )

    st.markdown(
        "### UID"
    )

    st.code(
        uid,
        language=None,
    )

    # --------------------------------------------------------
    # LIVE RISK RESULT
    # --------------------------------------------------------

    if (
        known_card
        and
        not score_table.empty
    ):

        detected_score = score_table[
            score_table["Card"]
            == card_id
        ]

        if not detected_score.empty:

            result = (
                detected_score.iloc[0]
            )

            observed_score = result[
                "Observed-Factor Score"
            ]

            coverage = result[
                "Evidence Coverage (%)"
            ]

            preliminary_score = result[
                "Preliminary Baseline Score"
            ]

            st.subheader(
                "Detected Card Risk Result"
            )

            r1, r2, r3 = st.columns(3)

            with r1:

                if pd.isna(
                    observed_score
                ):

                    st.metric(
                        "Observed-Factor Score",
                        "Pending",
                    )

                else:

                    st.metric(
                        "Observed-Factor Score",
                        f"{int(observed_score)}/100",
                    )

            with r2:

                st.metric(
                    "Evidence Coverage",
                    f"{int(coverage)}%",
                )

            with r3:

                st.metric(
                    "Final Cox Score",
                    "Pending",
                )

            if pd.isna(
                preliminary_score
            ):

                st.warning(
                    "Observed-factor score is available, "
                    "but the formal preliminary baseline "
                    "score is pending because evidence "
                    "coverage is below 80%."
                )

            else:

                st.success(
                    "Preliminary Unweighted "
                    f"Baseline Score: "
                    f"{int(preliminary_score)}/100"
                )

            st.info(
                "The Observed-Factor Score uses only "
                "currently supported security-factor "
                "evidence. UNKNOWN values are not guessed. "
                "This is NOT the final Cox-calibrated "
                "N1 risk score."
            )

    st.caption(
        f"Latest scan: {timestamp}"
    )


# ============================================================
# COMPACT BUTTON NAVIGATION
# ============================================================

if "dashboard_section" not in st.session_state:
    st.session_state.dashboard_section = "Live Scan"


def select_section(name):
    st.session_state.dashboard_section = name


nav1, nav2, nav3, nav4, nav5 = st.columns(5)

with nav1:
    st.button(
        "📡 Live Scan",
        use_container_width=True,
        type="primary" if st.session_state.dashboard_section == "Live Scan" else "secondary",
        on_click=select_section,
        args=("Live Scan",),
    )

with nav2:
    st.button(
        "🧮 Scoring",
        use_container_width=True,
        type="primary" if st.session_state.dashboard_section == "Scoring" else "secondary",
        on_click=select_section,
        args=("Scoring",),
    )

with nav3:
    st.button(
        "🪪 Cards & Evidence",
        use_container_width=True,
        type="primary" if st.session_state.dashboard_section == "Cards & Evidence" else "secondary",
        on_click=select_section,
        args=("Cards & Evidence",),
    )

with nav4:
    st.button(
        "⏱️ Timing & Trials",
        use_container_width=True,
        type="primary" if st.session_state.dashboard_section == "Timing & Trials" else "secondary",
        on_click=select_section,
        args=("Timing & Trials",),
    )

with nav5:
    st.button(
        "📊 Cox & Status",
        use_container_width=True,
        type="primary" if st.session_state.dashboard_section == "Cox & Status" else "secondary",
        on_click=select_section,
        args=("Cox & Status",),
    )

st.divider()


# ============================================================
# HELPER: LIVE SCORE BREAKDOWN
# ============================================================

FACTOR_LABELS = {
    "uid_writable": "UID Writable",
    "auth_type": "Authentication",
    "default_key_present": "Default Key Present",
    "lock_state": "Lock State",
    "ndef_protection": "NDEF Protection",
    "cve_flag": "CVE Flag",
}


def render_live_score_breakdown():
    live_status = load_live_status()

    if not live_status:
        return

    if not live_status.get("known_card", False):
        return

    card_id = str(live_status.get("card_id", "UNKNOWN"))

    if configs.empty or "card_instance" not in configs.columns:
        return

    matched = configs[
        configs["card_instance"].astype(str) == card_id
    ]

    if matched.empty:
        return

    row = matched.iloc[0]

    breakdown_rows = []
    score_values = []
    applicable = 0
    known = 0

    for factor in CORE_FACTORS:
        raw_value = row.get(factor, "UNKNOWN")
        encoded = encode_factor(factor, raw_value)

        if encoded == "NA":
            status = "Not Applicable"
            risk_display = "—"
        else:
            applicable += 1

            if encoded is None:
                status = "Unknown"
                risk_display = "—"
            else:
                known += 1
                score_values.append(float(encoded))
                status = "Known"
                risk_display = f"{float(encoded):g}"

        breakdown_rows.append(
            {
                "Security Factor": FACTOR_LABELS.get(factor, factor),
                "Value (configs.csv)": raw_value,
                "Risk Value": risk_display,
                "Status": status,
            }
        )

    st.subheader("Security Factor Breakdown")
    st.dataframe(
        pd.DataFrame(breakdown_rows),
        width="stretch",
        hide_index=True,
    )

    if score_values:
        score = round(sum(score_values) / len(score_values) * 100)
        coverage = round(known / applicable * 100) if applicable else 0

        value_text = " + ".join(f"{v:g}" for v in score_values)

        st.subheader("How the Score Was Calculated")
        st.code(
            f"({value_text}) / {len(score_values)} × 100 = {score}/100",
            language=None,
        )
        st.write(
            f"**Evidence Coverage:** {known} known / "
            f"{applicable} applicable × 100 = **{coverage}%**"
        )

        if score <= 33:
            band = "Low Risk"
        elif score <= 66:
            band = "Medium Risk"
        else:
            band = "High Risk"

        st.info(
            f"Prototype risk band: **{band}**. "
            "This band is based on the current unweighted prototype score, "
            "not the final Cox-calibrated model."
        )


# ============================================================
# SECTION 1 — LIVE SCAN
# ============================================================

if st.session_state.dashboard_section == "Live Scan":

    live_card_panel()

    st.divider()

    render_live_score_breakdown()

    st.caption(
        "Scan flow: Flipper Zero → UID identification → "
        "card configuration lookup → evidence-based prototype score."
    )


# ============================================================
# SECTION 2 — SCORING
# ============================================================

elif st.session_state.dashboard_section == "Scoring":

    st.header("🧮 N1 Evidence-Based Prototype Risk Scoring")

    st.info(
        "Observed-Factor Score = mean of known, applicable factor-risk values × 100. "
        "UNKNOWN values are excluded rather than guessed. "
        "Not Applicable values are excluded from both score and coverage."
    )

    if score_table.empty:
        st.warning("No configuration data available.")
    else:
        prototype_table = score_table[
            [
                "Card",
                "Family",
                "Observed-Factor Score",
                "Evidence Coverage (%)",
                "Preliminary Baseline Score",
                "Final Cox Score",
            ]
        ]

        st.dataframe(
            prototype_table,
            width="stretch",
            hide_index=True,
        )

    st.warning(
        "A high Observed-Factor Score with low evidence coverage "
        "must be interpreted cautiously."
    )

    st.subheader("Preliminary Unweighted Baseline")

    st.write(
        "The preliminary baseline is shown only when at least "
        "**80% of applicable core factors are known**."
    )

    if not score_table.empty:
        baseline_table = score_table[
            [
                "Config ID",
                "Card",
                "Family",
                "Preliminary Baseline Score",
                "Evidence Coverage (%)",
                "Baseline Status",
                "Final Cox Score",
            ]
        ]

        st.dataframe(
            baseline_table,
            width="stretch",
            hide_index=True,
        )

    st.caption(
        "Crypto1 = 0.5 is used only for the current preliminary "
        "equal-weight comparison. It is not a final Cox-derived weight."
    )

    st.subheader("Missing Evidence")

    if missing_table.empty:
        st.info("No configuration evidence available.")
    else:
        st.dataframe(
            missing_table,
            width="stretch",
            hide_index=True,
        )


# ============================================================
# SECTION 3 — CARDS & EVIDENCE
# ============================================================

elif st.session_state.dashboard_section == "Cards & Evidence":

    st.header("🪪 Cards & Security Evidence")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.metric("Lab Cards", len(lab_cards))

    with c2:
        st.metric("NTAG215", int((lab_cards["Family"] == "NTAG215").sum()))

    with c3:
        st.metric(
            "MIFARE Classic 1K",
            int((lab_cards["Family"] == "MIFARE Classic 1K").sum()),
        )

    with c4:
        st.metric("Unknown Core Values", unknown_core_count)

    st.subheader("Tested NFC Cards")

    st.dataframe(
        lab_cards,
        width="stretch",
        hide_index=True,
    )

    st.subheader("NFC Security Configuration Evidence")

    if configs.empty:
        st.warning("configs.csv is empty or unavailable.")
    else:
        st.dataframe(
            configs,
            width="stretch",
            hide_index=True,
        )

    st.caption(
        "The dashboard does not guess missing evidence. "
        "UNKNOWN values remain unresolved until supported by real laboratory "
        "or documented vulnerability evidence."
    )


# ============================================================
# SECTION 4 — TIMING & TRIALS
# ============================================================

elif st.session_state.dashboard_section == "Timing & Trials":

    st.header("⏱️ T2 Timing & Attack Trials")

    c1, c2, c3 = st.columns(3)

    with c1:
        st.metric("Automated Timing Trials", timing_trials)

    with c2:
        st.metric("Verified Modifications", verified_modifications)

    with c3:
        if average_verified_time is None:
            average_text = "N/A"
        else:
            average_text = f"{average_verified_time:.4f} s"

        st.metric("Average Verified Time", average_text)

    st.subheader("T2 – Flipper Zero Automated Modification Timing")

    if timing.empty:
        st.warning("No automated timing data available.")
    else:
        display_columns = [
            column
            for column in [
                "card_id",
                "tier",
                "repeat_no",
                "before_value",
                "after_value",
                "verified_modification_time_s",
                "modification_verified",
            ]
            if column in timing.columns
        ]

        st.dataframe(
            timing[display_columns],
            width="stretch",
            hide_index=True,
        )

        if (
            "card_id" in timing.columns
            and "verified_modification_time_s" in timing.columns
        ):
            chart_data = timing[
                ["card_id", "verified_modification_time_s"]
            ].copy()

            chart_data["verified_modification_time_s"] = pd.to_numeric(
                chart_data["verified_modification_time_s"],
                errors="coerce",
            )

            chart_data = chart_data.dropna()

            if not chart_data.empty:
                st.bar_chart(
                    chart_data,
                    x="card_id",
                    y="verified_modification_time_s",
                )

    st.caption(
        "Timing is host-assisted command-to-verified-readback time. "
        "It includes serial, CLI, device, NFC and verification overhead; "
        "it is not pure RF latency."
    )

    st.subheader("Attack Trial Summary")

    if attacks.empty:
        st.warning("No attack trial records available.")
    else:
        total_trials = len(attacks)

        compromised_trials = 0
        censored_trials = 0
        incomplete_trials = 0

        if "compromised" in attacks.columns:
            compromised_numeric = pd.to_numeric(
                attacks["compromised"],
                errors="coerce",
            )
            compromised_trials = int((compromised_numeric == 1).sum())
            incomplete_trials = int(compromised_numeric.isna().sum())

        if "censored" in attacks.columns:
            censored_numeric = pd.to_numeric(
                attacks["censored"],
                errors="coerce",
            )
            censored_trials = int((censored_numeric == 1).sum())

        a1, a2, a3, a4 = st.columns(4)

        with a1:
            st.metric("Total Trials", total_trials)

        with a2:
            st.metric("Compromised", compromised_trials)

        with a3:
            st.metric("Censored", censored_trials)

        with a4:
            st.metric("Incomplete", incomplete_trials)

        st.dataframe(
            attacks,
            width="stretch",
            hide_index=True,
        )

    st.info(
        "A successful controlled write does not automatically mean "
        "`compromised = 1`. Compromise is assigned only when the predefined "
        "compromise criterion is explicitly met."
    )


# ============================================================
# SECTION 5 — COX & STATUS
# ============================================================

elif st.session_state.dashboard_section == "Cox & Status":

    st.header("📊 Cox Model Readiness & Research Status")

    cox_ready = (
        unknown_core_count == 0
        and compromised_available
        and censored_available
    )

    if cox_ready:
        st.success(
            "Minimum dashboard readiness conditions are available. "
            "The dedicated readiness script must still pass before "
            "final Cox calibration."
        )
    else:
        st.error(
            "NOT READY – more real laboratory evidence is required "
            "before final Cox-derived weights."
        )

    r1, r2, r3 = st.columns(3)

    with r1:
        st.metric("Unknown Core Values", unknown_core_count)

    with r2:
        st.metric(
            "Compromised Outcome",
            "Available" if compromised_available else "Missing",
        )

    with r3:
        st.metric(
            "Censored Outcome",
            "Available" if censored_available else "Missing",
        )

    st.caption(
        "check_data_readiness.py performs stricter checks, including "
        "factor variation, complete configurations and usable attacker tiers."
    )

    st.subheader("Attacker Tier Evaluation Status")

    tier_status = pd.DataFrame(
        [
            {
                "Tier": "T1 – Smartphone",
                "Experimental Status": "Pending",
                "Reason": "Not experimentally populated yet",
            },
            {
                "Tier": "T2 – Flipper Zero",
                "Experimental Status": "Evaluated",
                "Reason": "Current real laboratory tier",
            },
            {
                "Tier": "T3 – Proxmark3",
                "Experimental Status": "Pending",
                "Reason": "Hardware not available",
            },
        ]
    )

    st.dataframe(
        tier_status,
        width="stretch",
        hide_index=True,
    )

    st.subheader("N1 Risk Scoring Pipeline")

    pipeline = pd.DataFrame(
        [
            {
                "Stage": "Security Factor Collection",
                "Status": (
                    "In Progress"
                    if unknown_core_count > 0
                    else "Implemented"
                ),
            },
            {
                "Stage": "T2 Flipper Zero Testing",
                "Status": "Implemented",
            },
            {
                "Stage": "Live NFC Card Detection",
                "Status": "Implemented",
            },
            {
                "Stage": "Automated Verified Timing",
                "Status": "Implemented",
            },
            {
                "Stage": "Observed-Factor 0–100 Score",
                "Status": "Implemented",
            },
            {
                "Stage": "Unweighted Baseline Score",
                "Status": "Implemented",
            },
            {
                "Stage": "Missing Evidence Detection",
                "Status": "Implemented",
            },
            {
                "Stage": "Cox Regression Calibration",
                "Status": "Pending more real data",
            },
            {
                "Stage": "Final Cox-Calibrated 0–100 Risk Score",
                "Status": "Pending calibration",
            },
        ]
    )

    st.dataframe(
        pipeline,
        width="stretch",
        hide_index=True,
    )

    st.subheader("Current Research Status")

    st.write(
        """
        The N1 prototype currently supports real NFC laboratory evidence,
        T2 Flipper Zero testing, automated verified modification timing,
        live NFC card identification, evidence-based observed-factor
        scoring, preliminary unweighted baseline scoring, missing-evidence
        detection and Cox-readiness checking.

        The final Cox-calibrated, attacker-tier-specific score remains
        pending until sufficient real compromised/censored outcomes and
        configuration variation are available.
        """
    )
