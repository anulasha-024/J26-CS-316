from pathlib import Path
import json

import pandas as pd
import streamlit as st


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
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = PROJECT_ROOT / "Datasets"

CONFIGS_FILE = DATASET_DIR / "configs.csv"
ATTACKS_FILE = DATASET_DIR / "attacks.csv"
TIMING_FILE = DATASET_DIR / "automated_timing.csv"

LIVE_STATUS_FILE = Path(__file__).with_name(
    "live_card_status.json"
)


# ============================================================
# REGISTERED LAB CARDS
# ============================================================

LAB_CARDS = pd.DataFrame(
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
            "Evidence": "32/32 keys found, 16/16 sectors read",
            "Status": "Baseline captured",
        },
        {
            "Card ID": "MIFARE1K_02",
            "Family": "MIFARE Classic 1K",
            "UID": "B7 22 FD 5F",
            "Evidence": "32/32 keys found, 16/16 sectors read",
            "Status": "Baseline captured",
        },
    ]
)


# ============================================================
# SECURITY FACTORS
# ============================================================

CORE_FACTORS = [
    "uid_writable",
    "auth_type",
    "default_key_present",
    "lock_state",
    "ndef_protection",
    "cve_flag",
]

FACTOR_LABELS = {
    "uid_writable": "UID Writable",
    "auth_type": "Authentication",
    "default_key_present": "Default Key Present",
    "lock_state": "Lock State",
    "ndef_protection": "NDEF Protection",
    "cve_flag": "CVE Flag",
}


# ============================================================
# LOAD FILES
# ============================================================

def load_csv(path):

    try:

        if path.exists():
            return pd.read_csv(path)

    except Exception as error:

        st.warning(
            f"Could not read {path.name}: {error}"
        )

    return pd.DataFrame()


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
# NORMALIZATION
# ============================================================

def normalize_value(value):

    if pd.isna(value):
        return ""

    return str(value).strip().lower()


def normalize_uid(value):

    value = (
        str(value)
        .upper()
        .replace(":", " ")
        .replace("-", " ")
    )

    return " ".join(
        value.split()
    )


# ============================================================
# SECURITY FACTOR ENCODING
#
# 0   = safer
# 0.5 = medium
# 1   = risky
#
# UNKNOWN = excluded
# N/A     = excluded
# ============================================================

def encode_factor(
    factor,
    value,
):

    value = normalize_value(value)


    if value in [
        "",
        "unknown",
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
            return 0.5

        if (
            "aes" in value
            or
            "3des" in value
            or
            "desfire" in value
            or
            "strong" in value
        ):
            return 0.0


    # --------------------------------------------------------
    # DEFAULT KEY
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
            "default",
            "default key",
        ]:
            return 1.0

        if value in [
            "no",
            "false",
            "not present",
            "changed",
            "custom key",
        ]:
            return 0.0


    # --------------------------------------------------------
    # LOCK STATE
    # --------------------------------------------------------

    if factor == "lock_state":

        if value in [
            "unlocked",
            "not locked",
            "read/write",
            "read write",
        ]:
            return 1.0

        if value in [
            "partial",
            "partially locked",
            "partially protected",
        ]:
            return 0.5

        if value in [
            "locked",
            "fully locked",
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
            "read only",
            "readonly",
        ]:
            return 0.0


    # --------------------------------------------------------
    # CVE
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
# SCORE CALCULATION
# ============================================================

def calculate_score(row):

    values = []

    applicable = 0
    known = 0


    for factor in CORE_FACTORS:

        if factor not in row.index:

            applicable += 1
            continue


        encoded = encode_factor(
            factor,
            row[factor],
        )


        if encoded == "NA":
            continue


        applicable += 1


        if encoded is not None:

            known += 1

            values.append(
                float(encoded)
            )


    if (
        applicable == 0
        or
        len(values) == 0
    ):

        return None, 0


    score = round(
        sum(values)
        / len(values)
        * 100
    )


    coverage = round(
        known
        / applicable
        * 100
    )


    return score, coverage


def calculate_preliminary_score(row):

    score, coverage = (
        calculate_score(row)
    )


    if score is None:
        return None, coverage


    if coverage < 80:
        return None, coverage


    return score, coverage


# ============================================================
# CURRENT CARD CONTEXT
# ============================================================

def get_current_card():

    live = load_live_status()


    if not live:
        return None


    uid = normalize_uid(
        live.get(
            "uid",
            "UNKNOWN",
        )
    )


    family = str(
        live.get(
            "family",
            "UNKNOWN",
        )
    )


    tier = str(
        live.get(
            "tier",
            "T2 - Flipper Zero",
        )
    )


    timestamp = str(
        live.get(
            "timestamp",
            "UNKNOWN",
        )
    )


    matched = LAB_CARDS[
        LAB_CARDS[
            "UID"
        ].apply(normalize_uid)
        == uid
    ]


    if not matched.empty:

        card_row = matched.iloc[0]

        return {
            "registered": True,
            "card_id": str(
                card_row[
                    "Card ID"
                ]
            ),
            "family": str(
                card_row[
                    "Family"
                ]
            ),
            "uid": uid,
            "tier": tier,
            "timestamp": timestamp,
        }


    return {
        "registered": False,
        "card_id": "UNREGISTERED",
        "family": family,
        "uid": uid,
        "tier": tier,
        "timestamp": timestamp,
    }


# ============================================================
# CURRENT CARD CONFIG
# ============================================================

def current_config(
    configs,
    context,
):

    if context is None:
        return pd.DataFrame()


    if not context[
        "registered"
    ]:
        return pd.DataFrame()


    if (
        configs.empty
        or
        "card_instance"
        not in configs.columns
    ):

        return pd.DataFrame()


    return configs[
        configs[
            "card_instance"
        ].astype(str)
        ==
        context[
            "card_id"
        ]
    ].copy()


# ============================================================
# CURRENT CARD TIMING
# ============================================================

def current_timing(
    timing,
    context,
):

    if context is None:
        return pd.DataFrame()


    if not context[
        "registered"
    ]:
        return pd.DataFrame()


    if (
        timing.empty
        or
        "card_id"
        not in timing.columns
    ):

        return pd.DataFrame()


    return timing[
        timing[
            "card_id"
        ].astype(str)
        ==
        context[
            "card_id"
        ]
    ].copy()


# ============================================================
# CURRENT CARD ATTACK TRIALS
# ============================================================

def current_attacks(
    attacks,
    config_rows,
    context,
):

    if context is None:
        return pd.DataFrame()


    if not context[
        "registered"
    ]:
        return pd.DataFrame()


    if attacks.empty:
        return pd.DataFrame()


    if (
        config_rows.empty
        or
        "config_id"
        not in config_rows.columns
        or
        "config_id"
        not in attacks.columns
    ):

        return pd.DataFrame()


    config_ids = (
        config_rows[
            "config_id"
        ]
        .astype(str)
        .tolist()
    )


    return attacks[
        attacks[
            "config_id"
        ].astype(str)
        .isin(config_ids)
    ].copy()


# ============================================================
# MISSING EVIDENCE
# ============================================================

def missing_factors(row):

    missing = []


    for factor in CORE_FACTORS:

        if factor not in row.index:

            missing.append(
                factor
            )

            continue


        encoded = encode_factor(
            factor,
            row[factor],
        )


        if encoded is None:

            missing.append(
                factor
            )


    return missing


# ============================================================
# SCAN CONTEXT DISPLAY
# ============================================================

def display_scan_context(context):

    if context is None:

        st.info(
            "No live NFC card scan available."
        )

        return


    if context[
        "registered"
    ]:

        st.success(
            "✅ REGISTERED LAB CARD DETECTED"
        )


    else:

        st.warning(
            "⚠️ NFC CARD DETECTED — UNREGISTERED CARD"
        )


    c1, c2, c3, c4 = st.columns(
        4
    )


    with c1:

        st.metric(
            "Card ID",
            context[
                "card_id"
            ],
        )


    with c2:

        st.metric(
            "Family",
            context[
                "family"
            ],
        )


    with c3:

        st.metric(
            "Attacker Tier",
            context[
                "tier"
            ],
        )


    with c4:

        st.metric(
            "Registry Status",
            (
                "Registered"
                if context[
                    "registered"
                ]
                else
                "Not Registered"
            ),
        )


    st.markdown(
        "### UID"
    )


    st.code(
        context[
            "uid"
        ],
        language=None,
    )


# ============================================================
# GLOBAL COX STATUS
# ============================================================

def calculate_global_cox_status(
    configs,
    attacks,
):

    unknown_count = 0


    if not configs.empty:

        for _, row in configs.iterrows():

            unknown_count += len(
                missing_factors(
                    row
                )
            )


    compromised_available = False
    censored_available = False


    if (
        not attacks.empty
        and
        "compromised"
        in attacks.columns
    ):

        values = pd.to_numeric(
            attacks[
                "compromised"
            ],
            errors="coerce",
        )


        compromised_available = bool(
            (
                values
                == 1
            ).any()
        )


    if (
        not attacks.empty
        and
        "censored"
        in attacks.columns
    ):

        values = pd.to_numeric(
            attacks[
                "censored"
            ],
            errors="coerce",
        )


        censored_available = bool(
            (
                values
                == 1
            ).any()
        )


    ready = (
        unknown_count == 0
        and
        compromised_available
        and
        censored_available
    )


    return (
        ready,
        unknown_count,
        compromised_available,
        censored_available,
    )


# ============================================================
# NAVIGATION
# ============================================================

if (
    "dashboard_section"
    not in st.session_state
):

    st.session_state.dashboard_section = (
        "Live Scan"
    )


def select_section(name):

    st.session_state.dashboard_section = (
        name
    )


navigation = [
    (
        "📡 Live Scan",
        "Live Scan",
    ),
    (
        "🧮 Scoring",
        "Scoring",
    ),
    (
        "🪪 Cards & Evidence",
        "Cards & Evidence",
    ),
    (
        "⏱️ Timing & Trials",
        "Timing & Trials",
    ),
    (
        "📊 Cox & Status",
        "Cox & Status",
    ),
]


for (
    column,
    (
        label,
        section,
    ),
) in zip(
    st.columns(5),
    navigation,
):


    with column:

        st.button(
            label,

            use_container_width=True,

            type=(
                "primary"
                if
                st.session_state.dashboard_section
                == section
                else
                "secondary"
            ),

            on_click=select_section,

            args=(
                section,
            ),
        )


st.divider()


# ============================================================
# PAGE 1 — LIVE SCAN
# ============================================================

@st.fragment(
    run_every="2s"
)
def live_scan_page():

    configs = load_csv(
        CONFIGS_FILE
    )

    context = get_current_card()


    st.header(
        "📡 Live NFC Card Detection"
    )


    display_scan_context(
        context
    )


    if context is None:
        return


    # --------------------------------------------------------
    # UNREGISTERED CARD
    # --------------------------------------------------------

    if not context[
        "registered"
    ]:

        st.subheader(
            "Detected Card Risk Result"
        )


        c1, c2, c3 = st.columns(
            3
        )


        with c1:

            st.metric(
                "Observed-Factor Score",
                "Pending",
            )


        with c2:

            st.metric(
                "Evidence Coverage",
                "Pending",
            )


        with c3:

            st.metric(
                "Final Cox Score",
                "Pending",
            )


        st.warning(
            "The NFC card was detected, but it is not "
            "registered in the laboratory dataset."
        )


        st.info(
            "Security factors have not been experimentally "
            "verified for this card. Therefore, the system "
            "does not generate a fabricated score."
        )

        return


    # --------------------------------------------------------
    # CONFIG
    # --------------------------------------------------------

    config_rows = current_config(
        configs,
        context,
    )


    if config_rows.empty:

        st.warning(
            "Registered card detected, but no matching "
            "configuration exists in configs.csv."
        )

        return


    row = config_rows.iloc[
        0
    ]


    score, coverage = (
        calculate_score(
            row
        )
    )


    preliminary_score, _ = (
        calculate_preliminary_score(
            row
        )
    )


    st.subheader(
        "Detected Card Risk Result"
    )


    c1, c2, c3 = st.columns(
        3
    )


    with c1:

        st.metric(
            "Observed-Factor Score",
            (
                "Pending"
                if score is None
                else
                f"{score}/100"
            ),
        )


    with c2:

        st.metric(
            "Evidence Coverage",
            f"{coverage}%",
        )


    with c3:

        st.metric(
            "Final Cox Score",
            "Pending",
        )


    if preliminary_score is None:

        st.warning(
            "Preliminary baseline score is pending because "
            "evidence coverage is below 80%."
        )


    else:

        st.success(
            "Preliminary Unweighted Baseline Score: "
            f"{preliminary_score}/100"
        )


    st.info(
        "This is the observed-factor prototype score. "
        "It is not the final Cox-calibrated score."
    )


    st.caption(
        f"Latest scan: "
        f"{context['timestamp']}"
    )


    st.divider()


    # --------------------------------------------------------
    # SECURITY FACTOR BREAKDOWN
    # --------------------------------------------------------

    breakdown_rows = []

    score_values = []

    applicable = 0
    known = 0


    for factor in CORE_FACTORS:

        raw_value = row.get(
            factor,
            "UNKNOWN",
        )


        encoded = encode_factor(
            factor,
            raw_value,
        )


        if encoded == "NA":

            factor_status = (
                "Not Applicable"
            )

            risk_display = "—"


        else:

            applicable += 1


            if encoded is None:

                factor_status = (
                    "Unknown"
                )

                risk_display = "—"


            else:

                known += 1

                score_values.append(
                    float(encoded)
                )

                factor_status = (
                    "Known"
                )

                risk_display = (
                    f"{float(encoded):g}"
                )


        breakdown_rows.append(
            {
                "Security Factor":
                    FACTOR_LABELS.get(
                        factor,
                        factor,
                    ),

                "Value (configs.csv)":
                    raw_value,

                "Risk Value":
                    risk_display,

                "Status":
                    factor_status,
            }
        )


    st.subheader(
        "Security Factor Breakdown — "
        f"{context['card_id']}"
    )


    st.dataframe(
        pd.DataFrame(
            breakdown_rows
        ),

        width="stretch",

        hide_index=True,
    )


    # --------------------------------------------------------
    # CALCULATION
    # --------------------------------------------------------

    if score_values:

        live_score = round(
            sum(score_values)
            / len(score_values)
            * 100
        )


        live_coverage = (

            round(
                known
                / applicable
                * 100
            )

            if applicable

            else 0
        )


        values_text = " + ".join(
            f"{value:g}"
            for value
            in score_values
        )


        st.subheader(
            "How the Score Was Calculated"
        )


        st.markdown(
            f"**Calculation for "
            f"{context['card_id']}:**"
        )


        st.markdown(
            f"`({values_text}) / "
            f"{len(score_values)} "
            f"× 100 = "
            f"{live_score}/100`"
        )


        st.write(
            f"**Evidence Coverage:** "
            f"{known} known / "
            f"{applicable} applicable "
            f"× 100 = "
            f"**{live_coverage}%**"
        )


        if live_score <= 33:

            band = "Low Risk"

        elif live_score <= 66:

            band = "Medium Risk"

        else:

            band = "High Risk"


        st.info(
            f"Prototype risk band: "
            f"**{band}**"
        )


# ============================================================
# PAGE 2 — SCORING
# ============================================================

@st.fragment(
    run_every="2s"
)
def scoring_page():

    configs = load_csv(
        CONFIGS_FILE
    )

    context = get_current_card()


    st.header(
        "🧮 Current NFC Card Security Score"
    )


    display_scan_context(
        context
    )


    if context is None:
        return


    if not context[
        "registered"
    ]:

        st.warning(
            "No registered security profile exists "
            "for this NFC card."
        )


        st.metric(
            "Observed Score",
            "Pending",
        )

        return


    config_rows = current_config(
        configs,
        context,
    )


    if config_rows.empty:

        st.warning(
            "No matching configuration found."
        )

        return


    table_rows = []


    for _, row in config_rows.iterrows():

        score, coverage = (
            calculate_score(
                row
            )
        )


        preliminary_score, _ = (
            calculate_preliminary_score(
                row
            )
        )


        table_rows.append(
            {
                "Card":
                    context[
                        "card_id"
                    ],

                "Family":
                    context[
                        "family"
                    ],

                "Observed-Factor Score":
                    score,

                "Evidence Coverage (%)":
                    coverage,

                "Preliminary Baseline Score":
                    (
                        preliminary_score
                        if preliminary_score
                        is not None
                        else
                        "Pending"
                    ),

                "Final Cox Score":
                    "Pending",
            }
        )


    st.dataframe(
        pd.DataFrame(
            table_rows
        ),

        width="stretch",

        hide_index=True,
    )


    st.caption(
        "UNKNOWN factors are excluded rather than guessed. "
        "Not Applicable factors are excluded."
    )


# ============================================================
# PAGE 3 — CARDS & EVIDENCE
# ============================================================

@st.fragment(
    run_every="2s"
)
def cards_evidence_page():

    configs = load_csv(
        CONFIGS_FILE
    )

    context = get_current_card()


    st.header(
        "🪪 Current Card & Security Evidence"
    )


    display_scan_context(
        context
    )


    if context is None:
        return


    if not context[
        "registered"
    ]:

        st.warning(
            "This card is not registered in the "
            "N1 laboratory evidence registry."
        )


        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "UID":
                            context[
                                "uid"
                            ],

                        "Family":
                            context[
                                "family"
                            ],

                        "Registry Status":
                            "Unregistered",

                        "Security Evidence":
                            "Not collected",

                        "Risk Score":
                            "Pending",
                    }
                ]
            ),

            width="stretch",

            hide_index=True,
        )

        return


    registered_card = LAB_CARDS[
        LAB_CARDS[
            "Card ID"
        ]
        ==
        context[
            "card_id"
        ]
    ]


    st.subheader(
        "Registered Card"
    )


    st.dataframe(
        registered_card,

        width="stretch",

        hide_index=True,
    )


    config_rows = current_config(
        configs,
        context,
    )


    st.subheader(
        "Security Configuration Evidence"
    )


    if config_rows.empty:

        st.warning(
            "No configuration evidence available."
        )

        return


    st.dataframe(
        config_rows,

        width="stretch",

        hide_index=True,
    )


    row = config_rows.iloc[
        0
    ]


    missing = missing_factors(
        row
    )


    st.subheader(
        "Missing Evidence"
    )


    if missing:

        st.warning(
            ", ".join(
                FACTOR_LABELS.get(
                    factor,
                    factor,
                )
                for factor
                in missing
            )
        )


    else:

        st.success(
            "All core security factors "
            "have evidence."
        )


# ============================================================
# PAGE 4 — TIMING & TRIALS
# ============================================================

@st.fragment(
    run_every="2s"
)
def timing_trials_page():

    configs = load_csv(
        CONFIGS_FILE
    )

    timing = load_csv(
        TIMING_FILE
    )

    attacks = load_csv(
        ATTACKS_FILE
    )

    context = get_current_card()


    st.header(
        "⏱️ Current Card Timing & Attack Trials"
    )


    display_scan_context(
        context
    )


    if context is None:
        return


    if not context[
        "registered"
    ]:

        st.warning(
            "No timing or attack-trial history "
            "is available for this unregistered card."
        )

        return


    config_rows = current_config(
        configs,
        context,
    )


    card_timing = current_timing(
        timing,
        context,
    )


    card_attacks = current_attacks(
        attacks,
        config_rows,
        context,
    )


    # --------------------------------------------------------
    # TIMING SUMMARY
    # --------------------------------------------------------

    timing_count = len(
        card_timing
    )

    verified_count = 0
    average_time = None


    if (
        not card_timing.empty
        and
        "modification_verified"
        in card_timing.columns
    ):

        verified_values = pd.to_numeric(
            card_timing[
                "modification_verified"
            ],
            errors="coerce",
        )


        verified_count = int(
            (
                verified_values
                == 1
            ).sum()
        )


    if (
        not card_timing.empty
        and
        "verified_modification_time_s"
        in card_timing.columns
    ):

        time_values = pd.to_numeric(
            card_timing[
                "verified_modification_time_s"
            ],
            errors="coerce",
        ).dropna()


        if not time_values.empty:

            average_time = (
                time_values.mean()
            )


    c1, c2, c3 = st.columns(
        3
    )


    with c1:

        st.metric(
            "Timing Trials",
            timing_count,
        )


    with c2:

        st.metric(
            "Verified Modifications",
            verified_count,
        )


    with c3:

        st.metric(
            "Average Verified Time",
            (
                "N/A"
                if average_time is None
                else
                f"{average_time:.4f} s"
            ),
        )


    st.subheader(
        f"T2 Timing Trials — "
        f"{context['card_id']}"
    )


    if card_timing.empty:

        st.info(
            "No timing records are currently "
            "available for this card."
        )


    else:

        st.dataframe(
            card_timing,

            width="stretch",

            hide_index=True,
        )


        if (
            "repeat_no"
            in card_timing.columns
            and
            "verified_modification_time_s"
            in card_timing.columns
        ):

            chart_data = card_timing[
                [
                    "repeat_no",
                    "verified_modification_time_s",
                ]
            ].copy()


            chart_data[
                "verified_modification_time_s"
            ] = pd.to_numeric(
                chart_data[
                    "verified_modification_time_s"
                ],
                errors="coerce",
            )


            chart_data = (
                chart_data.dropna()
            )


            if not chart_data.empty:

                chart_data[
                    "repeat_no"
                ] = (
                    chart_data[
                        "repeat_no"
                    ]
                    .astype(str)
                )


                st.bar_chart(
                    chart_data,

                    x="repeat_no",

                    y="verified_modification_time_s",
                )


    st.caption(
        "Timing is host-assisted "
        "command-to-verified-readback time. "
        "It includes serial, CLI, device, NFC and "
        "verification overhead; it is not pure RF latency."
    )


    # --------------------------------------------------------
    # ATTACK TRIALS
    # --------------------------------------------------------

    st.subheader(
        f"Attack Trials — "
        f"{context['card_id']}"
    )


    if card_attacks.empty:

        st.info(
            "No attack-trial records are currently "
            "available for this card."
        )


    else:

        compromised_count = 0
        censored_count = 0
        incomplete_count = 0


        if (
            "compromised"
            in card_attacks.columns
        ):

            compromised_values = pd.to_numeric(
                card_attacks[
                    "compromised"
                ],
                errors="coerce",
            )


            compromised_count = int(
                (
                    compromised_values
                    == 1
                ).sum()
            )


            incomplete_count = int(
                compromised_values
                .isna()
                .sum()
            )


        if (
            "censored"
            in card_attacks.columns
        ):

            censored_values = pd.to_numeric(
                card_attacks[
                    "censored"
                ],
                errors="coerce",
            )


            censored_count = int(
                (
                    censored_values
                    == 1
                ).sum()
            )


        a1, a2, a3, a4 = st.columns(
            4
        )


        with a1:

            st.metric(
                "Total Trials",
                len(
                    card_attacks
                ),
            )


        with a2:

            st.metric(
                "Compromised",
                compromised_count,
            )


        with a3:

            st.metric(
                "Censored",
                censored_count,
            )


        with a4:

            st.metric(
                "Incomplete",
                incomplete_count,
            )


        st.dataframe(
            card_attacks,

            width="stretch",

            hide_index=True,
        )


    st.info(
        "A successful controlled write does not automatically "
        "mean compromised = 1. Compromise is recorded only "
        "when the predefined compromise criterion is met."
    )


# ============================================================
# PAGE 5 — COX & STATUS
# ============================================================

@st.fragment(
    run_every="2s"
)
def cox_status_page():

    configs = load_csv(
        CONFIGS_FILE
    )

    attacks = load_csv(
        ATTACKS_FILE
    )

    context = get_current_card()


    st.header(
        "📊 Cox Model Readiness & Research Status"
    )


    display_scan_context(
        context
    )


    # --------------------------------------------------------
    # CURRENT CARD
    # --------------------------------------------------------

    st.subheader(
        "Current Scanned Card Status"
    )


    if context is None:

        st.info(
            "No current card scan."
        )


    elif not context[
        "registered"
    ]:

        st.warning(
            "Unregistered card — no security score "
            "or Cox-calibrated score can be assigned."
        )


    else:

        config_rows = current_config(
            configs,
            context,
        )


        if not config_rows.empty:

            row = config_rows.iloc[
                0
            ]


            score, coverage = (
                calculate_score(
                    row
                )
            )


            missing = missing_factors(
                row
            )


            c1, c2, c3 = st.columns(
                3
            )


            with c1:

                st.metric(
                    "Observed Score",
                    (
                        "Pending"
                        if score is None
                        else
                        f"{score}/100"
                    ),
                )


            with c2:

                st.metric(
                    "Evidence Coverage",
                    f"{coverage}%",
                )


            with c3:

                st.metric(
                    "Final Cox Score",
                    "Pending",
                )


            if missing:

                st.warning(
                    "Missing evidence: "
                    +
                    ", ".join(
                        FACTOR_LABELS.get(
                            factor,
                            factor,
                        )
                        for factor
                        in missing
                    )
                )


            else:

                st.success(
                    "Current card core security "
                    "evidence is complete."
                )


    st.divider()


    # --------------------------------------------------------
    # GLOBAL COX READINESS
    # --------------------------------------------------------

    st.subheader(
        "Global Dataset Cox Readiness"
    )


    (
        ready,
        unknown_count,
        compromised_available,
        censored_available,
    ) = calculate_global_cox_status(
        configs,
        attacks,
    )


    if ready:

        st.success(
            "Minimum dashboard readiness conditions are "
            "available. The dedicated readiness checker "
            "must still pass before final Cox calibration."
        )


    else:

        st.error(
            "NOT READY – more real laboratory evidence "
            "is required before final Cox-derived weights."
        )


    c1, c2, c3 = st.columns(
        3
    )


    with c1:

        st.metric(
            "Unknown Core Values",
            unknown_count,
        )


    with c2:

        st.metric(
            "Compromised Outcome",
            (
                "Available"
                if compromised_available
                else
                "Missing"
            ),
        )


    with c3:

        st.metric(
            "Censored Outcome",
            (
                "Available"
                if censored_available
                else
                "Missing"
            ),
        )


    st.caption(
        "Cox regression readiness remains a global "
        "dataset-level property because the model requires "
        "multiple configurations and outcome variation."
    )


    st.subheader(
        "Attacker Tier Evaluation Status"
    )


    tier_status = pd.DataFrame(
        [
            {
                "Tier":
                    "T1 – Smartphone",

                "Experimental Status":
                    "Pending",

                "Reason":
                    "Not experimentally populated yet",
            },

            {
                "Tier":
                    "T2 – Flipper Zero",

                "Experimental Status":
                    "Evaluated",

                "Reason":
                    "Current real laboratory tier",
            },

            {
                "Tier":
                    "T3 – Proxmark3",

                "Experimental Status":
                    "Pending",

                "Reason":
                    "Hardware not available",
            },
        ]
    )


    st.dataframe(
        tier_status,

        width="stretch",

        hide_index=True,
    )


    st.subheader(
        "N1 Risk Scoring Pipeline"
    )


    pipeline = pd.DataFrame(
        [
            {
                "Stage":
                    "Security Factor Collection",
                "Status":
                    "In Progress",
            },
            {
                "Stage":
                    "T2 Flipper Zero Testing",
                "Status":
                    "Implemented",
            },
            {
                "Stage":
                    "Live NFC Card Detection",
                "Status":
                    "Implemented",
            },
            {
                "Stage":
                    "Scanned Card Auto Context",
                "Status":
                    "Implemented",
            },
            {
                "Stage":
                    "Automated Verified Timing",
                "Status":
                    "Implemented",
            },
            {
                "Stage":
                    "Observed-Factor 0–100 Score",
                "Status":
                    "Implemented",
            },
            {
                "Stage":
                    "Cox Regression Calibration",
                "Status":
                    "Pending more real data",
            },
            {
                "Stage":
                    "Final Cox-Calibrated Risk Score",
                "Status":
                    "Pending calibration",
            },
        ]
    )


    st.dataframe(
        pipeline,

        width="stretch",

        hide_index=True,
    )


# ============================================================
# PAGE ROUTER
# ============================================================

section = (
    st.session_state.dashboard_section
)


if section == "Live Scan":

    live_scan_page()


elif section == "Scoring":

    scoring_page()


elif section == "Cards & Evidence":

    cards_evidence_page()


elif section == "Timing & Trials":

    timing_trials_page()


elif section == "Cox & Status":

    cox_status_page()