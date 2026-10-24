(function () {
    "use strict";

    const API = "/api/statistics";

    function createElement(tag, className, text) {
        const element = document.createElement(tag);

        if (className) {
            element.className = className;
        }

        if (text !== undefined) {
            element.textContent = String(text);
        }

        return element;
    }

    function installStyles() {
        if (document.getElementById("n3-statistics-style")) {
            return;
        }

        const style = document.createElement("style");
        style.id = "n3-statistics-style";

        style.textContent = `
            #n3-statistics-view[hidden] {
                display: none !important;
            }

            #n3-statistics-view {
                padding: 24px 0;
            }

            .n3-stats-heading {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 16px;
                flex-wrap: wrap;
                margin-bottom: 24px;
            }

            .n3-stats-heading h2 {
                margin: 0 0 8px;
                font-size: 24px;
            }

            .n3-stats-muted {
                color: #94a3b8;
                font-size: 13px;
                line-height: 1.6;
            }

            .n3-stats-refresh {
                border: 1px solid #475569;
                background: #1e293b;
                color: #f8fafc;
                border-radius: 8px;
                padding: 10px 18px;
                cursor: pointer;
            }

            .n3-stats-grid {
                display: grid;
                grid-template-columns: repeat(
                    auto-fit,
                    minmax(170px, 1fr)
                );
                gap: 16px;
                margin-bottom: 24px;
            }

            .n3-stats-card,
            .n3-stats-panel {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 12px;
                padding: 20px;
            }

            .n3-stats-card-label {
                color: #94a3b8;
                font-size: 13px;
                margin-bottom: 12px;
            }

            .n3-stats-card-value {
                color: #f8fafc;
                font-size: 28px;
                font-weight: 700;
            }

            .n3-stats-panels {
                display: grid;
                grid-template-columns: repeat(
                    auto-fit,
                    minmax(280px, 1fr)
                );
                gap: 20px;
                margin-bottom: 24px;
            }

            .n3-stats-panel h3 {
                margin: 0 0 20px;
                font-size: 17px;
                color: #f8fafc;
            }

            .n3-stats-bar-row {
                margin-bottom: 18px;
            }

            .n3-stats-bar-label {
                display: flex;
                justify-content: space-between;
                gap: 10px;
                color: #cbd5e1;
                font-size: 13px;
                margin-bottom: 7px;
            }

            .n3-stats-bar-track {
                height: 12px;
                background: #0f172a;
                border-radius: 8px;
                overflow: hidden;
            }

            .n3-stats-bar-fill {
                height: 100%;
                border-radius: 8px;
                background: #38bdf8;
            }

            .n3-stats-latency {
                display: grid;
                grid-template-columns: repeat(
                    auto-fit,
                    minmax(150px, 1fr)
                );
                gap: 16px;
            }

            .n3-stats-note {
                margin-top: 20px;
                color: #94a3b8;
                font-size: 12px;
                line-height: 1.7;
            }
        `;

        document.head.appendChild(style);
    }

    function addCard(container, label, value) {
        const card = createElement("div", "n3-stats-card");
        const title = createElement(
            "div",
            "n3-stats-card-label",
            label
        );
        const number = createElement(
            "div",
            "n3-stats-card-value",
            value
        );

        card.append(title, number);
        container.appendChild(card);
    }

    function createBarPanel(title, counts, total) {
        const panel = createElement(
            "section",
            "n3-stats-panel"
        );

        panel.appendChild(createElement("h3", "", title));

        Object.entries(counts).forEach(([label, count]) => {
            const value = Number(count) || 0;
            const percentage = total > 0
                ? (value / total) * 100
                : 0;

            const row = createElement(
                "div",
                "n3-stats-bar-row"
            );

            const labelRow = createElement(
                "div",
                "n3-stats-bar-label"
            );

            labelRow.appendChild(
                createElement("span", "", label)
            );

            labelRow.appendChild(
                createElement(
                    "span",
                    "",
                    `${value} (${percentage.toFixed(1)}%)`
                )
            );

            const track = createElement(
                "div",
                "n3-stats-bar-track"
            );

            const fill = createElement(
                "div",
                "n3-stats-bar-fill"
            );

            fill.style.width = `${Math.min(
                100,
                Math.max(0, percentage)
            )}%`;

            track.appendChild(fill);
            row.append(labelRow, track);
            panel.appendChild(row);
        });

        return panel;
    }

    function formatLatency(value) {
        if (
            value === null ||
            value === undefined ||
            !Number.isFinite(Number(value))
        ) {
            return "N/A";
        }

        return `${Number(value).toFixed(3)} ms`;
    }

    function renderStatistics(data, container) {
        container.replaceChildren();

        const total = Number(data.total_scans) || 0;
        const verdicts = data.verdict_counts || {};
        const families = data.card_families || {};
        const changed = data.changed_layer_counts || {};
        const performance = data.performance || {};

        const cards = createElement(
            "div",
            "n3-stats-grid"
        );

        addCard(cards, "Total Scans", total);
        addCard(cards, "VALID", verdicts.VALID || 0);
        addCard(cards, "MODIFIED", verdicts.MODIFIED || 0);
        addCard(cards, "UNKNOWN", verdicts.UNKNOWN || 0);

        container.appendChild(cards);

        const panels = createElement(
            "div",
            "n3-stats-panels"
        );

        panels.appendChild(
            createBarPanel(
                "Verdict Distribution",
                verdicts,
                total
            )
        );

        panels.appendChild(
            createBarPanel(
                "Card Family Distribution",
                families,
                total
            )
        );

        panels.appendChild(
            createBarPanel(
                "Changed Verification Layers",
                changed,
                total
            )
        );

        container.appendChild(panels);

        const latencyPanel = createElement(
            "section",
            "n3-stats-panel"
        );

        latencyPanel.appendChild(
            createElement(
                "h3",
                "",
                "Verification Performance"
            )
        );

        const latencyCards = createElement(
            "div",
            "n3-stats-latency"
        );

        addCard(
            latencyCards,
            "Average Latency",
            formatLatency(performance.average_latency_ms)
        );

        addCard(
            latencyCards,
            "Minimum Latency",
            formatLatency(performance.minimum_latency_ms)
        );

        addCard(
            latencyCards,
            "Maximum Latency",
            formatLatency(performance.maximum_latency_ms)
        );

        addCard(
            latencyCards,
            "Latency Samples",
            performance.sample_count || 0
        );

        latencyPanel.appendChild(latencyCards);
        container.appendChild(latencyPanel);

        container.appendChild(
            createElement(
                "p",
                "n3-stats-note",
                `Statistics are calculated from stored verification reports. ` +
                `These counts represent scans, not unique cards or detection accuracy. ` +
                `Skipped reports: ${data.skipped_reports || 0}. ` +
                `Latency excludes NFC acquisition and report persistence.`
            )
        );
    }

    async function loadStatistics(container) {
        container.textContent = "Loading statistics...";

        try {
            const response = await fetch(API, {
                cache: "no-store"
            });

            if (!response.ok) {
                throw new Error(
                    `Statistics API returned HTTP ${response.status}`
                );
            }

            const data = await response.json();

            if (data.status !== "SUCCESS") {
                throw new Error("Statistics response is invalid.");
            }

            renderStatistics(data, container);

        } catch (error) {
            container.textContent =
                `Unable to load statistics: ${error.message}`;
        }
    }

    function initialize() {
        const main = document.querySelector(".main-content");

        const nav = Array.from(
            document.querySelectorAll(
                ".sidebar-nav .nav-item"
            )
        );

        const statisticsButton = nav.find(
            button =>
                button.textContent.trim().toLowerCase() ===
                "statistics"
        );

        if (!main || !statisticsButton) {
            console.error(
                "N3 Statistics: dashboard navigation not found."
            );
            return;
        }

        installStyles();

        const view = createElement(
            "section",
            "",
            ""
        );

        view.id = "n3-statistics-view";
        view.hidden = true;

        const heading = createElement(
            "div",
            "n3-stats-heading"
        );

        const titleBlock = createElement("div");

        titleBlock.appendChild(
            createElement("h2", "", "N3 Statistics")
        );

        titleBlock.appendChild(
            createElement(
                "p",
                "n3-stats-muted",
                "Verification results and system performance"
            )
        );

        const refresh = createElement(
            "button",
            "n3-stats-refresh",
            "Refresh Statistics"
        );

        refresh.type = "button";

        const content = createElement("div");

        heading.append(titleBlock, refresh);
        view.append(heading, content);

        main.appendChild(view);

        refresh.addEventListener(
            "click",
            () => loadStatistics(content)
        );

        // Other navigation handlers must be allowed
        // to run normally. Only hide this view here.
        nav.forEach(button => {
            if (button !== statisticsButton) {
                button.addEventListener(
                    "click",
                    () => {
                        view.hidden = true;
                    },
                    { capture: true }
                );
            }
        });

        statisticsButton.disabled = false;
        statisticsButton.removeAttribute("disabled");

        statisticsButton.addEventListener("click", () => {
            Array.from(main.children).forEach(child => {
                if (
                    child !== view &&
                    !child.classList.contains("top-header")
                ) {
                    child.hidden = true;
                }
            });

            view.hidden = false;

            nav.forEach(button => {
                button.classList.toggle(
                    "active",
                    button === statisticsButton
                );
            });

            loadStatistics(content);
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            initialize
        );
    } else {
        initialize();
    }
})();
