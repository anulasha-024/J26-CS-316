// ============================================================
// N3_TIVE — Scan History + Baseline Management navigation fix
// Reads existing Flask /api/history endpoints.
// Keeps externally installed Baseline Management navigation enabled.
// Does not change NFC acquisition or verification logic.
// ============================================================

(() => {
    "use strict";

    const HISTORY_API = "/api/history";
    const PAGE_SIZE = 20;
    let offset = 0;
    let total = 0;
    let hasMore = false;
    let currentRows = [];
    let requestSequence = 0;

    const byId = (id) => document.getElementById(id);

    function asText(value, fallback = "--") {
        if (value === null || value === undefined || value === "") {
            return fallback;
        }
        return String(value);
    }

    function escapeHtml(value) {
        return asText(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    function formatTime(value) {
        if (!value) return "--";
        const date = new Date(value);
        return Number.isNaN(date.getTime())
            ? asText(value)
            : date.toLocaleString();
    }

    async function readJson(url) {
        const response = await fetch(url, { cache: "no-store" });
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${url}`);
        }
        return response.json();
    }

    function setStatus(message, isError = false) {
        const status = byId("n3-history-status");
        status.textContent = message;
        status.style.color = isError ? "#fca5a5" : "#93c5fd";
    }

    function filteredRows() {
        const query = byId("n3-history-search").value.trim().toLowerCase();
        const verdict = byId("n3-history-verdict").value;
        return currentRows.filter((item) => {
            const searchData = [
                item.uid,
                item.card_family,
                item.card_type,
                item.scan_id,
            ].map((value) => asText(value)).join(" ").toLowerCase();
            return (!query || searchData.includes(query)) &&
                (!verdict || String(item.verdict || "").toUpperCase() === verdict);
        });
    }

    function renderRows() {
        const rows = filteredRows();
        const body = byId("n3-history-body");
        body.innerHTML = "";

        if (!rows.length) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 6;
            td.textContent = currentRows.length
                ? "No matching scans on this page. Change the filters or go to another page."
                : "No stored reports found.";
            tr.appendChild(td);
            body.appendChild(tr);
        }

        for (const item of rows) {
            const tr = document.createElement("tr");
            const decision = String(item.verdict || "UNKNOWN").toUpperCase();
            const color = decision === "VALID" ? "#10b981" :
                decision === "MODIFIED" ? "#fb7185" : "#fbbf24";

            tr.innerHTML = `
                <td>${escapeHtml(formatTime(item.verification_time_utc))}</td>
                <td>${escapeHtml(item.card_family || item.card_type)}</td>
                <td>${escapeHtml(item.uid)}</td>
                <td><strong style="color:${color}">${escapeHtml(decision)}</strong></td>
                <td>${escapeHtml(item.baseline_version == null ? "--" : `V${item.baseline_version}`)}</td>
                <td><button type="button" class="n3-history-action">View report</button></td>
            `;

            const button = tr.querySelector("button");
            if (!item.scan_id) {
                button.disabled = true;
                button.title = "No scan ID in this report";
            } else {
                button.addEventListener("click", () => openReport(item.scan_id));
            }
            body.appendChild(tr);
        }

        byId("n3-history-pages").textContent = total
            ? `Stored reports: ${total} · Page ${Math.floor(offset / PAGE_SIZE) + 1} · Showing ${rows.length} of ${currentRows.length} loaded`
            : "No reports";
        byId("n3-history-previous").disabled = offset === 0;
        byId("n3-history-next").disabled = !hasMore;
    }

    async function loadHistory() {
        const requestId = ++requestSequence;
        setStatus("Loading saved verification reports...");
        byId("n3-history-refresh").disabled = true;

        try {
            const data = await readJson(
                `${HISTORY_API}?limit=${PAGE_SIZE}&offset=${offset}`
            );
            if (requestId !== requestSequence) return;
            if (!Array.isArray(data.history)) {
                throw new Error("Unexpected history response. Confirm /api/history is installed.");
            }
            currentRows = data.history;
            total = Number(data.total) || 0;
            hasMore = Boolean(data.has_more);
            renderRows();
            setStatus(
                `${currentRows.length} reports loaded. Filters apply to this page only.` +
                (data.skipped_invalid_reports
                    ? ` ${data.skipped_invalid_reports} damaged report(s) skipped.`
                    : "")
            );
        } catch (error) {
            if (requestId !== requestSequence) return;
            currentRows = [];
            total = 0;
            hasMore = false;
            renderRows();
            setStatus(
                `Unable to load Scan History: ${error.message}. ` +
                "Check that the updated dashboard/app.py is running.",
                true
            );
        } finally {
            if (requestId === requestSequence) {
                byId("n3-history-refresh").disabled = false;
            }
        }
    }

    function firstChange(report) {
        const raw = report.raw_memory || {};
        const change = (raw.changed_pages || [])[0] ||
            (raw.changed_blocks || [])[0];
        if (!change) return "No confirmed raw-memory changes";
        const location = change.page != null
            ? `Page ${change.page}`
            : `Block ${change.block_number ?? change.block ?? "--"}`;
        return `${location} · ${asText(change.region)}`;
    }

    function applicationSummary(report) {
        const application = report.application_ndef || {};
        const oldMarker = application.baseline_marker || {};
        const newMarker = application.current_marker || {};
        if (oldMarker.text != null || newMarker.text != null) {
            return {
                oldValue: asText(oldMarker.text, "Not available"),
                newValue: asText(newMarker.text, "Not available"),
            };
        }
        const change = (application.changed_fields || [])[0];
        if (change) {
            return {
                oldValue: asText(change.old_value),
                newValue: asText(change.new_value),
            };
        }
        return null;
    }

    async function openReport(scanId) {
        const details = byId("n3-history-detail");
        details.hidden = false;
        details.textContent = "Loading selected report...";

        try {
            const report = await readJson(
                `${HISTORY_API}/${encodeURIComponent(scanId)}`
            );
            const card = report.card || {};
            const decision = report.final_decision || {};
            const journal = report.journal_state || {};
            const application = applicationSummary(report);
            const layer = decision.layer_statuses || {};

            details.innerHTML = `
                <div class="n3-history-detail-header">
                    <h3>Selected Verification Report</h3>
                    <button type="button" id="n3-history-close">Close details</button>
                </div>
                <div class="n3-history-summary">
                    <div><small>Card / UID</small><strong>${escapeHtml(card.card_family || card.card_type)} · ${escapeHtml(card.uid)}</strong></div>
                    <div><small>Verdict</small><strong>${escapeHtml(decision.verdict)}</strong></div>
                    <div><small>Application / NDEF</small><strong>${escapeHtml(report.application_ndef?.status || layer.APPLICATION_NDEF)}</strong></div>
                    <div><small>Raw Memory</small><strong>${escapeHtml(report.raw_memory?.status || layer.RAW_MEMORY)}</strong></div>
                    <div><small>Security State</small><strong>${escapeHtml(report.security_state?.status || layer.SECURITY_STATE)}</strong></div>
                    <div><small>Journal</small><strong>${escapeHtml(journal.journal_status)}</strong></div>
                    <div><small>Tamper Location</small><strong>${escapeHtml(firstChange(report))}</strong></div>
                    <div><small>Verified At</small><strong>${escapeHtml(formatTime(report.verification_time_utc))}</strong></div>
                </div>
                ${application ? `
                    <div class="n3-history-app-change">
                        <strong>Application change</strong>
                        <p>Original: ${escapeHtml(application.oldValue)}</p>
                        <p>Current: ${escapeHtml(application.newValue)}</p>
                    </div>
                ` : ""}
                <details class="n3-history-json">
                    <summary>View complete JSON evidence</summary>
                    <pre id="n3-history-json-text"></pre>
                </details>
            `;
            byId("n3-history-json-text").textContent = JSON.stringify(report, null, 2);
            byId("n3-history-close").addEventListener("click", () => {
                details.hidden = true;
            });
        } catch (error) {
            details.textContent = `Could not load selected report: ${error.message}`;
        }
    }

    function createHistoryView() {
        const history = document.createElement("section");
        history.id = "n3-history-view";
        history.className = "panel n3-history-view";
        history.hidden = true;
        history.innerHTML = `
            <div class="panel-header n3-history-header">
                <div><h2>Scan History</h2><p>Stored N3 verification reports</p></div>
                <button type="button" id="n3-history-refresh" class="n3-history-action">Refresh</button>
            </div>
            <div class="n3-history-content">
                <div class="n3-history-filters">
                    <label>Filter this page by UID / card
                        <input type="search" id="n3-history-search" placeholder="UID or card type">
                    </label>
                    <label>Verdict
                        <select id="n3-history-verdict">
                            <option value="">All</option>
                            <option value="VALID">VALID</option>
                            <option value="MODIFIED">MODIFIED</option>
                            <option value="UNKNOWN">UNKNOWN</option>
                        </select>
                    </label>
                </div>
                <p id="n3-history-status" role="status"></p>
                <div class="table-wrapper">
                    <table class="n3-history-table">
                        <thead><tr>
                            <th>Scan time</th><th>Card family</th><th>UID</th>
                            <th>Verdict</th><th>Baseline</th><th>Details</th>
                        </tr></thead>
                        <tbody id="n3-history-body"></tbody>
                    </table>
                </div>
                <div class="n3-history-pagination">
                    <button id="n3-history-previous" type="button" class="n3-history-action">Previous</button>
                    <span id="n3-history-pages"></span>
                    <button id="n3-history-next" type="button" class="n3-history-action">Next</button>
                </div>
                <div id="n3-history-detail" hidden></div>
            </div>
        `;
        return history;
    }

    function injectStyles() {
        const style = document.createElement("style");
        style.textContent = `
            [hidden] { display: none !important; }
            .n3-history-view { margin-top: 20px; }
            .n3-history-header { display:flex; justify-content:space-between; align-items:center; gap:18px; }
            .n3-history-header p { margin:5px 0 0; color:#94a3b8; font-size:13px; }
            .n3-history-content { padding:20px; }
            .n3-history-filters { display:flex; flex-wrap:wrap; gap:16px; margin-bottom:12px; }
            .n3-history-filters label { display:flex; gap:8px; flex-direction:column; color:#93c5fd; font-size:13px; }
            .n3-history-filters input,.n3-history-filters select { background:#071728; border:1px solid #31516b; color:#f8fafc; border-radius:7px; padding:9px 11px; min-width:180px; }
            #n3-history-status { font-size:13px; margin:12px 0; }
            .n3-history-table { width:100%; border-collapse:collapse; }
            .n3-history-table th,.n3-history-table td { padding:12px; border-bottom:1px solid #1e3a50; text-align:left; font-size:13px; }
            .n3-history-table th { color:#93c5fd; }
            .n3-history-action,.n3-history-detail-header button { border:1px solid #2563eb; background:#0c3260; color:#eff6ff; padding:8px 12px; border-radius:7px; cursor:pointer; }
            .n3-history-action:hover,.n3-history-detail-header button:hover { background:#1555a0; }
            .n3-history-action:disabled { opacity:.45; cursor:not-allowed; }
            .n3-history-pagination { display:flex; gap:14px; justify-content:space-between; align-items:center; flex-wrap:wrap; margin-top:20px; color:#94a3b8; font-size:12px; }
            #n3-history-detail { border:1px solid #31516b; margin-top:24px; border-radius:10px; padding:18px; background:#071728; }
            .n3-history-detail-header { display:flex; align-items:center; justify-content:space-between; gap:12px; }
            .n3-history-detail-header h3 { margin:0; }
            .n3-history-summary { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin-top:16px; }
            .n3-history-summary>div { padding:12px; border:1px solid #1e3a50; border-radius:8px; min-width:0; overflow-wrap:anywhere; }
            .n3-history-summary small { display:block; color:#93c5fd; margin-bottom:7px; }
            .n3-history-summary strong { color:#f8fafc; font-size:13px; }
            .n3-history-app-change { margin-top:16px; overflow-wrap:anywhere; }
            .n3-history-json { margin-top:18px; }
            .n3-history-json pre { white-space:pre-wrap; overflow-wrap:anywhere; max-height:420px; overflow-y:auto; }
            .sidebar-nav .nav-item:disabled { opacity:.55; cursor:not-allowed; }
        `;
        document.head.appendChild(style);
    }

    function initialize() {
        const main = document.querySelector(".main-content");
        const navButtons = document.querySelectorAll(".sidebar-nav .nav-item");
        if (!main || navButtons.length < 2) {
            console.error("N3 Scan History: required dashboard layout not found.");
            return;
        }

        injectStyles();
        // Preserve dashboard sections, but do not claim third-party views
        // created by the separate Baseline Management installer.
        const dashboardItems = Array.from(main.children).filter((el) => {
            const label = `${el.id || ""} ${el.className || ""}`;
            return !el.classList.contains("top-header") &&
                   !/baseline|journal|statistic|history/i.test(label);
        });
        const history = createHistoryView();
        main.appendChild(history);

        const dashboardButton = navButtons[0];
        const historyButton = navButtons[1];

        // Hide the installed Baseline Management screen when a different
        // navigation tab becomes active. Its own script handles reopening it.
        function hideBaselineView() {
            for (const element of Array.from(main.children)) {
                const label = `${element.id || ""} ${element.className || ""}`;
                if (/baseline/i.test(label) && !dashboardItems.includes(element)) {
                    element.hidden = true;
                }
            }
        }

        function showView(name) {
            const isHistory = name === "history";
            hideBaselineView();
            for (const item of dashboardItems) item.hidden = isHistory;
            history.hidden = !isHistory;
            dashboardButton.classList.toggle("active", !isHistory);
            historyButton.classList.toggle("active", isHistory);
            if (isHistory) loadHistory();
        }

        dashboardButton.addEventListener("click", () => showView("dashboard"));
        historyButton.addEventListener("click", () => showView("history"));

        // IMPORTANT: Baseline Management is installed separately and is the
        // third sidebar item. Do not disable it from this history script.
        const baselineButton = navButtons[2];
        if (baselineButton) {
            baselineButton.disabled = false;
            baselineButton.removeAttribute("disabled");

            // The Baseline Management installer owns its own screen and API.
            // Here we only close the Scan History screen and the dashboard
            // summary to avoid overlaying multiple views.
            baselineButton.addEventListener("click", () => {
                history.hidden = true;
                for (const item of dashboardItems) item.hidden = true;
                historyButton.classList.remove("active");
            });
        }

        // Journal & Audit and Statistics are still future sections.
        // Leave their original availability unchanged so their own
        // installers can enable them when implemented.

        byId("n3-history-refresh").addEventListener("click", loadHistory);
        byId("n3-history-search").addEventListener("input", renderRows);
        byId("n3-history-verdict").addEventListener("change", renderRows);
        byId("n3-history-previous").addEventListener("click", () => {
            offset = Math.max(0, offset - PAGE_SIZE);
            byId("n3-history-detail").hidden = true;
            loadHistory();
        });
        byId("n3-history-next").addEventListener("click", () => {
            if (!hasMore) return;
            offset += PAGE_SIZE;
            byId("n3-history-detail").hidden = true;
            loadHistory();
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize);
    } else {
        initialize();
    }
})();
