// ============================================================
// N3_TIVE DASHBOARD — FULL JAVASCRIPT
// Live reader state + verification reports + readable changes
// ============================================================

const LATEST_REPORT_API = "/api/latest";
const RUNTIME_STATE_API = "/api/runtime";
const REFRESH_INTERVAL_MS = 250;
const RUNTIME_REFRESH_INTERVAL_MS = 150;

let latestRenderedReport = null;
let latestReportRequestInProgress = false;
let runtimeRequestInProgress = false;

// ------------------------------------------------------------
// COMMON HELPERS
// ------------------------------------------------------------

function getElement(id) {
    return document.getElementById(id);
}

function displayValue(value, fallback = "--") {
    if (value === null || value === undefined || value === "") {
        return fallback;
    }

    if (typeof value === "object") {
        return JSON.stringify(value);
    }

    return String(value);
}

function setText(id, value, fallback = "--") {
    const element = getElement(id);

    if (element) {
        element.textContent = displayValue(value, fallback);
    }
}

function formatVersion(value) {
    return value === null || value === undefined
        ? "--"
        : `V${value}`;
}

function formatBoolean(value) {
    return value === true
        ? "YES"
        : value === false
            ? "NO"
            : "--";
}

function formatTime(value) {
    if (!value) {
        return "--";
    }

    const date = new Date(value);

    return Number.isNaN(date.getTime())
        ? String(value)
        : date.toLocaleString();
}

function escapeHtml(value) {
    return displayValue(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

// ------------------------------------------------------------
// HEX TO HUMAN-READABLE TEXT
// ------------------------------------------------------------

// Decode hexadecimal application evidence only when
// the complete value is valid printable UTF-8.
//
// Raw memory evidence is never changed by this function.

function readableHexText(value) {
    if (typeof value !== "string") {
        return null;
    }

    const cleaned = value.trim();

    if (!/^(?:[0-9A-Fa-f]{2}(?:[\s:-]+|$))+$/.test(cleaned)) {
        return null;
    }

    const tokens = cleaned
        .split(/[\s:-]+/)
        .filter(Boolean);

    if (!tokens.length) {
        return null;
    }

    const bytes = tokens.map(
        token => parseInt(token, 16)
    );

    while (
        bytes.length &&
        bytes[bytes.length - 1] === 0
    ) {
        bytes.pop();
    }

    if (!bytes.length) {
        return null;
    }

    try {
        const decoded = new TextDecoder(
            "utf-8",
            {
                fatal: true
            }
        ).decode(
            new Uint8Array(bytes)
        );

        if (
            !decoded ||
            /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\uFFFD]/.test(decoded)
        ) {
            return null;
        }

        return decoded;

    } catch (error) {
        return null;
    }
}

function readableApplicationValue(text, blockHex) {
    if (
        text !== null &&
        text !== undefined &&
        text !== ""
    ) {
        return String(text);
    }

    return (
        readableHexText(blockHex) ??
        blockHex ??
        null
    );
}

// ------------------------------------------------------------
// LIVE RUNTIME BANNER
// ------------------------------------------------------------

function getRuntimeBanner() {
    let banner = getElement("n3-runtime-banner");

    if (banner) {
        return banner;
    }

    banner = document.createElement("div");
    banner.id = "n3-runtime-banner";

    Object.assign(
        banner.style,
        {
            position: "fixed",
            top: "72px",
            right: "20px",
            zIndex: "9999",
            maxWidth: "430px",
            padding: "11px 16px",
            borderRadius: "10px",
            fontFamily: "inherit",
            fontWeight: "700",
            fontSize: "13px",
            lineHeight: "1.45",
            border: "1px solid #334155",
            background: "#0f172a",
            color: "#e2e8f0",
            boxShadow: "0 8px 30px rgba(0,0,0,0.30)"
        }
    );

    document.body.appendChild(banner);

    return banner;
}

function reportCompletesRuntimeState(runtime) {
    if (
        !latestRenderedReport ||
        !runtime?.updated_at_utc
    ) {
        return false;
    }

    const reportTime = new Date(
        latestRenderedReport.verification_time_utc
    ).getTime();

    const runtimeTime = new Date(
        runtime.updated_at_utc
    ).getTime();

    return (
        Number.isFinite(reportTime) &&
        Number.isFinite(runtimeTime) &&
        reportTime >= runtimeTime
    );
}

function renderRuntimeState(runtime) {
    const banner = getRuntimeBanner();

    let status = String(
        runtime?.status || "STARTING"
    ).toUpperCase();

    let message = runtime?.message || "";

    if (
        status === "VERIFYING" &&
        reportCompletesRuntimeState(runtime)
    ) {
        const verdict = (
            latestRenderedReport.final_decision?.verdict ||
            "COMPLETE"
        );

        status = "RESULT";

        message = `Verification complete: ${verdict}`;
    }

    banner.textContent = message
        ? `${status} — ${message}`
        : status;

    const colors = {
        READY: [
            "#10b981",
            "#6ee7b7",
            "#0f172a"
        ],
        SCANNING: [
            "#f59e0b",
            "#fbbf24",
            "#1c1917"
        ],
        VERIFYING: [
            "#38bdf8",
            "#7dd3fc",
            "#082f49"
        ],
        RESULT: [
            "#22c55e",
            "#86efac",
            "#052e16"
        ],
        ERROR: [
            "#ef4444",
            "#fca5a5",
            "#450a0a"
        ]
    };

    const [border, text, background] = (
        colors[status] || [
            "#64748b",
            "#cbd5e1",
            "#0f172a"
        ]
    );

    banner.style.borderColor = border;
    banner.style.color = text;
    banner.style.background = background;
}

async function fetchRuntimeState() {
    if (runtimeRequestInProgress) {
        return;
    }

    runtimeRequestInProgress = true;

    try {
        const response = await fetch(
            RUNTIME_STATE_API,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        renderRuntimeState(
            await response.json()
        );

    } catch (error) {
        console.error(
            "N3 runtime state update failed:",
            error
        );

        renderRuntimeState({
            status: "ERROR",
            message: "Live reader status is unavailable."
        });

    } finally {
        runtimeRequestInProgress = false;
    }
}

// ------------------------------------------------------------
// VERDICT AND VERIFICATION LAYERS
// ------------------------------------------------------------

function applyLayerStatus(elementId, status) {
    const element = getElement(elementId);

    if (!element) {
        return;
    }

    const normalized = String(
        status || "UNKNOWN"
    ).toUpperCase();

    element.textContent = normalized;

    element.classList.remove(
        "layer-match",
        "layer-changed",
        "layer-unknown"
    );

    element.classList.add(
        normalized === "MATCH"
            ? "layer-match"
            : normalized === "CHANGED"
                ? "layer-changed"
                : "layer-unknown"
    );
}

function applyVerdict(verdict, reason) {
    const card = getElement("verdict-card");
    const value = getElement("verdict");
    const detail = getElement("verdict-reason");

    if (!card || !value || !detail) {
        return;
    }

    const normalized = String(
        verdict || "UNKNOWN"
    ).toUpperCase();

    value.textContent = normalized;

    detail.textContent = (
        reason ||
        "No verification reason is available."
    );

    card.classList.remove(
        "verdict-valid",
        "verdict-modified",
        "verdict-unknown"
    );

    card.classList.add(
        normalized === "VALID"
            ? "verdict-valid"
            : normalized === "MODIFIED"
                ? "verdict-modified"
                : "verdict-unknown"
    );
}

// ------------------------------------------------------------
// CARD INFORMATION
// ------------------------------------------------------------

function renderCardInformation(report) {
    const card = report.card || {};
    const reader = report.reader_metadata || {};

    setText(
        "card-type",
        card.card_type,
        "Unknown NFC Card"
    );

    setText(
        "card-family",
        card.card_family
    );

    setText(
        "card-uid",
        card.uid
    );

    setText(
        "reader-name",
        reader.reader_name
    );

    setText(
        "source-file",
        reader.source_file
    );
}

// ------------------------------------------------------------
// VERDICT AND BASELINE INFORMATION
// ------------------------------------------------------------

function renderVerdictAndBaseline(report) {
    const decision = report.final_decision || {};
    const baseline = report.baseline || {};
    const rollback = report.rollback_evidence || {};
    const journal = report.journal_state || {};

    applyVerdict(
        decision.verdict,
        decision.reason
    );

    setText(
        "active-baseline",
        formatVersion(
            rollback.active_baseline_version
        )
    );

    setText(
        "baseline-used",
        formatVersion(
            baseline.baseline_version
        )
    );

    setText(
        "latest-authorized",
        formatVersion(
            journal.latest_authorized_version
        )
    );
}

// ------------------------------------------------------------
// THREE-LAYER VERIFICATION
// ------------------------------------------------------------

function renderVerificationLayers(report) {
    applyLayerStatus(
        "layer-application",
        report.application_ndef?.status
    );

    applyLayerStatus(
        "layer-memory",
        report.raw_memory?.status
    );

    applyLayerStatus(
        "layer-security",
        report.security_state?.status
    );
}

// ------------------------------------------------------------
// EXACT MEMORY CHANGE LOCATION
// ------------------------------------------------------------

// This function identifies the real changed memory
// location, including block, page and sector.

function getFirstMemoryChange(report) {
    const memory = report.raw_memory || {};

    const blocks = memory.changed_blocks || [];
    const pages = memory.changed_pages || [];

    if (blocks.length) {
        const change = blocks[0];

        return {
            type: "BLOCK",

            number:
                change.block_number ??
                change.block,

            sector:
                change.sector_number ??
                change.sector,

            blockType:
                change.block_type,

            region:
                change.region,

            oldValue:
                change.old_value,

            newValue:
                change.new_value
        };
    }

    if (pages.length) {
        const change = pages[0];

        return {
            type: "PAGE",

            number:
                change.page,

            sector:
                null,

            blockType:
                null,

            region:
                change.region,

            oldValue:
                change.old_value,

            newValue:
                change.new_value
        };
    }

    return null;
}

// ------------------------------------------------------------
// HUMAN-READABLE APPLICATION CHANGE
// ------------------------------------------------------------

// This function uses application-layer evidence.
//
// When available, decoded application text is
// preferred over raw hexadecimal values.

function getApplicationChange(report) {
    const application = report.application_ndef || {};

    if (
        String(
            application.status || ""
        ).toUpperCase() !== "CHANGED"
    ) {
        return null;
    }

    const before = application.baseline_marker || {};
    const after = application.current_marker || {};

    const hasMarkerEvidence = [
        before.text,
        after.text,
        before.block_hex,
        after.block_hex
    ].some(
        value =>
            value !== null &&
            value !== undefined &&
            value !== ""
    );

    if (hasMarkerEvidence) {
        return {
            type: "APPLICATION",

            number:
                after.block_number ??
                before.block_number ??
                null,

            sector:
                after.sector_number ??
                before.sector_number ??
                null,

            blockType:
                after.block_type ??
                before.block_type ??
                "APPLICATION_DATA",

            region:
                "APPLICATION_DATA",

            oldValue:
                readableApplicationValue(
                    before.text,
                    before.block_hex
                ),

            newValue:
                readableApplicationValue(
                    after.text,
                    after.block_hex
                )
        };
    }

    // Use changed application fields if marker
    // information is unavailable.

    const fields = application.changed_fields || [];

    if (!fields.length) {
        return null;
    }

    // Prefer text-related application fields.

    const selected = fields.find(
        change =>
            /text|payload|message|content|marker|ndef/i.test(
                String(change.field || "")
            )
    ) || fields[0];

    return {
        type:
            "APPLICATION",

        number:
            null,

        sector:
            null,

        blockType:
            selected.field || "APPLICATION_DATA",

        region:
            "APPLICATION_DATA",

        oldValue:
            readableHexText(selected.old_value) ??
            selected.old_value,

        newValue:
            readableHexText(selected.new_value) ??
            selected.new_value
    };
}

// ------------------------------------------------------------
// TAMPER LOCALIZATION AND CHANGED VALUES
// ------------------------------------------------------------

// IMPORTANT:
//
// Tamper Localization:
//     Raw memory has priority.
//
// Changed Values:
//     Human-readable application data has priority.
//
// This separates forensic memory evidence from
// human-readable application evidence.

function renderTamperLocalization(report) {
    const classes = report.tamper_classification || [];

    setText(
        "tamper-classification",
        Array.isArray(classes) && classes.length
            ? classes.join(", ")
            : "NO_CONFIRMED_CHANGE"
    );

    // --------------------------------------------------------
    // FIND ACTUAL MEMORY LOCATION
    // --------------------------------------------------------

    const locationChange = (
        getFirstMemoryChange(report) ||
        getApplicationChange(report)
    );

    // --------------------------------------------------------
    // FIND APPLICATION TEXT FOR DISPLAY
    // --------------------------------------------------------

    const applicationChange = (
        getApplicationChange(report)
    );

    const displayChange = (
        applicationChange &&
        (
            applicationChange.oldValue != null ||
            applicationChange.newValue != null
        )
    )
        ? applicationChange
        : locationChange;

    // --------------------------------------------------------
    // NO CONFIRMED CHANGE
    // --------------------------------------------------------

    if (!locationChange) {
        setText(
            "tamper-sector",
            "--"
        );

        setText(
            "tamper-unit",
            "--"
        );

        setText(
            "tamper-type",
            "--"
        );

        setText(
            "tamper-region",
            "--"
        );

        setText(
            "old-value",
            "No confirmed change"
        );

        setText(
            "new-value",
            "No confirmed change"
        );

        return;
    }

    // --------------------------------------------------------
    // EXACT TAMPER LOCATION
    // --------------------------------------------------------

    setText(
        "tamper-sector",
        locationChange.sector
    );

    setText(
        "tamper-unit",
        locationChange.number == null
            ? locationChange.type
            : `${locationChange.type} ${locationChange.number}`
    );

    setText(
        "tamper-type",
        locationChange.blockType
    );

    setText(
        "tamper-region",
        locationChange.region
    );

    // --------------------------------------------------------
    // ORIGINAL / MODIFIED APPLICATION VALUES
    // --------------------------------------------------------

    setText(
        "old-value",
        displayChange?.oldValue,
        "Not available"
    );

    setText(
        "new-value",
        displayChange?.newValue,
        "Not available"
    );
}

// ------------------------------------------------------------
// JOURNAL, ROLLBACK AND TIME EVIDENCE
// ------------------------------------------------------------

function renderJournalAndTime(report) {
    const journal = report.journal_state || {};
    const rollback = report.rollback_evidence || {};
    const time = report.time_evidence || {};

    setText(
        "journal-status",
        journal.journal_status
    );

    setText(
        "rollback-detected",
        formatBoolean(
            rollback.rollback_detected
        )
    );

    setText(
        "rollback-version",
        formatVersion(
            rollback.matched_older_version
        )
    );

    setText(
        "time-status",
        time.status
    );

    setText(
        "last-valid-time",
        formatTime(
            time.last_known_valid_utc
        )
    );

    setText(
        "first-modified-time",
        formatTime(
            time.first_detected_modified_utc
        )
    );
}

// ------------------------------------------------------------
// PERFORMANCE AND SCAN TIME
// ------------------------------------------------------------

function renderPerformance(report) {
    const latency = (
        report.performance_metrics?.verification_latency_ms
    );

    setText(
        "scan-time",
        formatTime(
            report.verification_time_utc
        )
    );

    setText(
        "latency",
        latency == null ||
        !Number.isFinite(Number(latency))
            ? "--"
            : `${Number(latency).toFixed(3)} ms`
    );
}

// ------------------------------------------------------------
// RAW MEMORY CHANGE EVIDENCE
// ------------------------------------------------------------

// Preserve original hexadecimal evidence in
// the Raw Memory Change Evidence section.

function renderMemoryChanges(report) {
    const container = getElement(
        "memory-change-container"
    );

    if (!container) {
        return;
    }

    const memory = report.raw_memory || {};
    const changes = [];

    // --------------------------------------------------------
    // MIFARE CLASSIC CHANGED BLOCKS
    // --------------------------------------------------------

    for (
        const change of memory.changed_blocks || []
    ) {
        changes.push({
            label:
                `Sector ${
                    change.sector_number ??
                    change.sector ??
                    "--"
                } / Block ${
                    change.block_number ??
                    change.block ??
                    "--"
                }`,

            region:
                change.region || "UNKNOWN_REGION",

            oldValue:
                change.old_value,

            newValue:
                change.new_value
        });
    }

    // --------------------------------------------------------
    // NTAG CHANGED PAGES
    // --------------------------------------------------------

    for (
        const change of memory.changed_pages || []
    ) {
        changes.push({
            label:
                `Page ${change.page ?? "--"}`,

            region:
                change.region || "UNKNOWN_REGION",

            oldValue:
                change.old_value,

            newValue:
                change.new_value
        });
    }

    // --------------------------------------------------------
    // NO CHANGES
    // --------------------------------------------------------

    if (!changes.length) {
        container.innerHTML = `
            <p class="empty-message">
                No confirmed raw-memory changes.
            </p>
        `;

        return;
    }

    container.innerHTML = "";

    // --------------------------------------------------------
    // DISPLAY RAW FORENSIC EVIDENCE
    // --------------------------------------------------------

    for (const change of changes) {
        const item = document.createElement("div");

        item.className = "memory-change";

        item.innerHTML = `
            <strong>
                ${escapeHtml(change.label)}
            </strong>

            <p>
                Region:
                ${escapeHtml(change.region)}
            </p>

            <p>
                Previous:
                ${escapeHtml(change.oldValue)}
            </p>

            <p>
                Current:
                ${escapeHtml(change.newValue)}
            </p>
        `;

        container.appendChild(item);
    }
}

// ------------------------------------------------------------
// RECENT SCAN PREVIEW
// ------------------------------------------------------------

function renderRecentScanPreview(report) {
    const body = getElement(
        "recent-scans-body"
    );

    if (!body) {
        return;
    }

    const card = report.card || {};
    const decision = report.final_decision || {};

    body.innerHTML = `
        <tr>
            <td>
                ${escapeHtml(
                    formatTime(
                        report.verification_time_utc
                    )
                )}
            </td>

            <td>
                ${escapeHtml(
                    card.card_family
                )}
            </td>

            <td>
                ${escapeHtml(
                    card.uid
                )}
            </td>

            <td>
                ${escapeHtml(
                    decision.verdict
                )}
            </td>
        </tr>
    `;
}

// ------------------------------------------------------------
// NO REPORT STATE
// ------------------------------------------------------------

function renderNoReportState(message) {
    setText(
        "card-type",
        "Waiting for scan..."
    );

    setText(
        "card-family",
        "--"
    );

    setText(
        "card-uid",
        "--"
    );

    applyVerdict(
        "UNKNOWN",
        message ||
        "No verification report is available."
    );
}

// ------------------------------------------------------------
// FULL REPORT RENDERER
// ------------------------------------------------------------

function renderReport(report) {
    if (
        report.status === "NO_REPORT" ||
        report.status === "ERROR"
    ) {
        renderNoReportState(
            report.message
        );

        return;
    }

    latestRenderedReport = report;

    renderCardInformation(report);

    renderVerdictAndBaseline(report);

    renderVerificationLayers(report);

    renderTamperLocalization(report);

    renderJournalAndTime(report);

    renderPerformance(report);

    renderMemoryChanges(report);

    renderRecentScanPreview(report);
}

// ------------------------------------------------------------
// FETCH LATEST REPORT
// ------------------------------------------------------------

async function fetchLatestReport() {
    if (latestReportRequestInProgress) {
        return;
    }

    latestReportRequestInProgress = true;

    try {
        const response = await fetch(
            LATEST_REPORT_API,
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }

        const report = await response.json();

        renderReport(report);

    } catch (error) {
        console.error(
            "N3 dashboard update failed:",
            error
        );

        applyVerdict(
            "UNKNOWN",
            "Dashboard could not retrieve the latest N3 verification report."
        );

    } finally {
        latestReportRequestInProgress = false;
    }
}

// ------------------------------------------------------------
// START THE LIVE DASHBOARD
// ------------------------------------------------------------

document.addEventListener(
    "DOMContentLoaded",
    () => {
        fetchLatestReport();

        fetchRuntimeState();

        setInterval(
            fetchLatestReport,
            REFRESH_INTERVAL_MS
        );

        setInterval(
            fetchRuntimeState,
            RUNTIME_REFRESH_INTERVAL_MS
        );
    }
);