// =============================================================
// N3_TIVE Baseline Management (read-only)
// Connects to /api/baselines without altering dashboard.js.
// =============================================================
(() => {
    "use strict";

    const API = "/api/baselines";
    const get = (id) => document.getElementById(id);
    const el = (tag, cls, text) => {
        const element = document.createElement(tag);
        if (cls) element.className = cls;
        if (text !== undefined) element.textContent = String(text);
        return element;
    };
    const safe = (value, fallback = "--") =>
        value === null || value === undefined || value === "" ? fallback : String(value);
    const versionText = (number) =>
        number === null || number === undefined ? "--" : `V${number}`;
    const displayTime = (value) => {
        if (!value) return "--";
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
    };
    let busy = false;
    let cachedCards = [];

    function addStyles() {
        const style = el("style");
        style.textContent = `
            #n3-baseline-view { margin-top:20px; }
            #n3-baseline-view[hidden] { display:none!important; }
            .n3-baseline-head { display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap; }
            .n3-baseline-body { padding:20px; }
            .n3-baseline-head p { margin:5px 0 0;color:#94a3b8;font-size:13px; }
            .n3-baseline-chip { border:1px solid #1d5e74;border-radius:99px;color:#86efac;padding:5px 10px;font-size:11px;white-space:nowrap; }
            .n3-baseline-refresh { background:#0e4b89;color:#eff6ff;border:1px solid #2b70b9;border-radius:7px;padding:8px 14px;cursor:pointer; }
            .n3-baseline-refresh:disabled { opacity:.6;cursor:wait; }
            .n3-baseline-message { min-height:20px;color:#93c5fd;font-size:13px; }
            .n3-baseline-cards { display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:16px;margin-top:16px; }
            .n3-baseline-card { border:1px solid #1d3e56;border-radius:12px;background:#071c30;padding:16px;min-width:0; }
            .n3-baseline-card h3 { margin:0;font-size:16px;color:#f8fafc; }
            .n3-baseline-uid { color:#93c5fd;overflow-wrap:anywhere;font-size:13px;margin:9px 0 14px; }
            .n3-baseline-metrics { display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin-bottom:15px; }
            .n3-baseline-metrics>div { background:#0d2941;border-radius:7px;padding:10px; }
            .n3-baseline-metrics small { display:block;color:#94a3b8;font-size:11px;margin-bottom:5px; }
            .n3-baseline-metrics strong { color:#f8fafc; }
            .n3-baseline-table { width:100%;border-collapse:collapse;font-size:12px; }
            .n3-baseline-table th,.n3-baseline-table td { padding:9px 5px;border-top:1px solid #24445b;text-align:left;overflow-wrap:anywhere; }
            .n3-baseline-table th { color:#93c5fd; }
            .n3-integrity-ok { color:#34d399;font-weight:700; }
            .n3-integrity-fail { color:#fca5a5;font-weight:700; }
            .n3-baseline-note { font-size:12px;color:#94a3b8;margin-top:16px;line-height:1.5; }
            #n3-baseline-search { background:#081b30;border:1px solid #31516b;border-radius:7px;color:#fff;padding:9px 12px;max-width:100%;min-width:230px; }
            .n3-baseline-controls { display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap; }
        `;
        document.head.appendChild(style);
    }

    function createView() {
        const section = el("section", "panel");
        section.id = "n3-baseline-view";
        section.hidden = true;

        const head = el("div", "panel-header n3-baseline-head");
        const titleBlock = el("div");
        titleBlock.appendChild(el("h2", "", "Baseline Management"));
        titleBlock.appendChild(el("p", "", "Trusted baseline versions and integrity status"));
        const chip = el("span", "n3-baseline-chip", "READ ONLY");
        head.append(titleBlock, chip);

        const body = el("div", "n3-baseline-body");
        const controls = el("div", "n3-baseline-controls");
        const search = el("input");
        search.id = "n3-baseline-search";
        search.type = "search";
        search.placeholder = "Filter by card family or UID";
        search.setAttribute("aria-label", "Filter baseline cards by UID or card family");
        const refresh = el("button", "n3-baseline-refresh", "Refresh");
        refresh.id = "n3-baseline-refresh";
        refresh.type = "button";
        controls.append(search, refresh);

        const status = el("p", "n3-baseline-message", "Open this tab to load saved baselines.");
        status.id = "n3-baseline-status";
        status.setAttribute("role", "status");
        const listing = el("div", "n3-baseline-cards");
        listing.id = "n3-baseline-list";
        body.append(controls, status, listing);
        body.appendChild(el("p", "n3-baseline-note",
            "Read-only viewer. The active version is set by the existing N3 trusted baseline manager, not by this page. " +
            "VERIFIED means a saved baseline passed its integrity check; this screen does not display secret keys or raw card memory."));
        section.append(head, body);
        return section;
    }

    function createVersionTable(versions) {
        const table = el("table", "n3-baseline-table");
        const head = el("thead");
        const hRow = el("tr");
        ["Version", "Role", "Integrity", "Enrolled"].forEach(name =>
            hRow.appendChild(el("th", "", name))
        );
        head.appendChild(hRow);
        const tbody = el("tbody");
        (versions || []).forEach((entry) => {
            const tr = el("tr");
            tr.appendChild(el("td", "", versionText(entry.version)));
            tr.appendChild(el("td", "", entry.is_active ? "ACTIVE" : "Stored"));
            const integrity = safe(entry.integrity, "NOT_VERIFIED");
            tr.appendChild(el("td", integrity === "VERIFIED" ? "n3-integrity-ok" : "n3-integrity-fail", integrity));
            tr.appendChild(el("td", "", displayTime(entry.enrollment_time_utc)));
            tbody.appendChild(tr);
        });
        table.append(head, tbody);
        return table;
    }

    function renderCards() {
        const listing = get("n3-baseline-list");
        listing.replaceChildren();
        const search = get("n3-baseline-search").value.trim().toLowerCase();
        const matches = cachedCards.filter(item =>
            `${safe(item.card_family)} ${safe(item.uid)}`.toLowerCase().includes(search)
        );
        if (!matches.length) {
            listing.appendChild(el("p", "n3-baseline-note", cachedCards.length
                ? "No enrolled cards match that search."
                : "No enrolled baselines were found in the configured baseline directory."));
            return;
        }
        matches.forEach((card) => {
            const box = el("article", "n3-baseline-card");
            box.appendChild(el("h3", "", safe(card.card_family)));
            box.appendChild(el("p", "n3-baseline-uid", `UID: ${safe(card.uid)}`));
            const metrics = el("div", "n3-baseline-metrics");
            for (const [label, value] of [
                ["Active baseline", versionText(card.active_version)],
                ["Latest version", versionText(card.latest_version)]
            ]) {
                const item = el("div");
                item.appendChild(el("small", "", label));
                item.appendChild(el("strong", "", value));
                metrics.appendChild(item);
            }
            box.appendChild(metrics);
            if (card.active_pointer_error) {
                box.appendChild(el("p", "n3-integrity-fail", "Active baseline pointer could not be validated."));
            }
            box.appendChild(createVersionTable(card.versions));
            box.appendChild(el("p", "n3-baseline-note",
                "Version evidence is read-only. Enrollment source files and trusted baseline data remain on the local backend."));
            listing.appendChild(box);
        });
    }

    async function loadBaselines() {
        if (busy) return;
        busy = true;
        const refresh = get("n3-baseline-refresh");
        const status = get("n3-baseline-status");
        refresh.disabled = true;
        status.textContent = "Loading stored trusted baselines...";
        try {
            const response = await fetch(API, { cache: "no-store" });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const data = await response.json();
            if (data.status !== "OK" || !Array.isArray(data.cards)) {
                throw new Error(data.message || "Unexpected API response");
            }
            cachedCards = data.cards;
            renderCards();
            status.textContent = `${data.total_cards} enrolled card(s), ${data.total_versions} version(s)` +
                (data.skipped_files ? `; ${data.skipped_files} unreadable metadata file(s) skipped.` : ".");
            status.style.color = "#93c5fd";
        } catch (error) {
            cachedCards = [];
            renderCards();
            status.style.color = "#fca5a5";
            status.textContent = `Cannot load baselines: ${error.message}. Check /api/baselines and restart N3.`;
        } finally {
            refresh.disabled = false;
            busy = false;
        }
    }

    function initialize() {
        const main = document.querySelector(".main-content");
        const navItems = document.querySelectorAll(".sidebar-nav .nav-item");
        if (!main || navItems.length < 3) {
            console.error("N3 Baseline Management: dashboard structure was not found.");
            return;
        }
        const dashboardButton = navItems[0];
        const historyButton = navItems[1];
        const baselineButton = navItems[2];
        const historyView = get("n3-history-view");
        const content = Array.from(main.children).filter(node =>
            !node.classList.contains("top-header")
        );

        addStyles();
        const baselineView = createView();
        main.appendChild(baselineView);
        baselineButton.disabled = false;
        baselineButton.title = "View trusted baseline versions";

        baselineButton.addEventListener("click", () => {
            for (const node of content) node.hidden = true;
            if (historyView) historyView.hidden = true;
            baselineView.hidden = false;
            navItems.forEach(button => button.classList.remove("active"));
            baselineButton.classList.add("active");
            loadBaselines();
        });

        // History.js handles restoring its own content when these buttons
        // are clicked. We only need to hide the baseline-only view.
        [dashboardButton, historyButton].forEach(button => {
            button.addEventListener("click", () => {
                baselineView.hidden = true;
                baselineButton.classList.remove("active");
            });
        });

        get("n3-baseline-search").addEventListener("input", renderCards);
        get("n3-baseline-refresh").addEventListener("click", loadBaselines);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", initialize);
    } else {
        initialize();
    }
})();
