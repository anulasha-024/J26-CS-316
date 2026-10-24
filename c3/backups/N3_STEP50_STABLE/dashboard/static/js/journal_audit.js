// N3_TIVE — Journal & Audit (read-only, report-derived)
// Installed in addition to existing dashboard/history/baseline scripts.
(() => {
    'use strict';

    const API = '/api/journal-audit';
    const PER_PAGE = 25;
    let offset = 0;
    let total = 0;
    let hasMore = false;
    let loading = false;
    let requestId = 0;
    let restoreVisibility = null;

    const el = (id) => document.getElementById(id);
    const safeText = (v, fallback = '--') => v === null || v === undefined || v === '' ? fallback : String(v);
    const dateText = (v) => {
        if (!v) return '--';
        const date = new Date(v);
        return Number.isNaN(date.getTime()) ? String(v) : date.toLocaleString();
    };

    function make(tag, text, cls) {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = safeText(text);
        if (cls) node.className = cls;
        return node;
    }

    const css = `
    .n3-audit-view{margin-top:18px;border:1px solid #21465f;border-radius:12px;background:#081c2b;color:#e8f4ff;padding:22px;}
    .n3-audit-title{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap}
    .n3-audit-title h2{font-size:19px;margin:0}.n3-audit-muted{color:#91b4d0;font-size:12px}
    .n3-audit-controls{display:flex;align-items:flex-end;flex-wrap:wrap;gap:12px;margin:20px 0 12px}
    .n3-audit-controls label{color:#91b4d0;font-size:12px;display:flex;flex-direction:column;gap:6px}
    .n3-audit-controls input,.n3-audit-controls select{border:1px solid #315675;border-radius:7px;background:#061826;color:#e8f4ff;padding:10px;min-width:145px}
    .n3-audit-button{border:1px solid #2877d6;border-radius:7px;padding:9px 13px;background:#10447e;color:#fff;cursor:pointer}
    .n3-audit-button:disabled{opacity:.4;cursor:not-allowed}
    .n3-audit-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:18px 0}
    .n3-audit-card{background:#0b273a;border:1px solid #234a62;border-radius:9px;padding:14px}
    .n3-audit-card span{display:block;font-size:12px;color:#91b4d0}.n3-audit-card strong{font-size:22px}
    .n3-audit-scroll{max-width:100%;overflow-x:auto}
    .n3-audit-table{width:100%;min-width:940px;border-collapse:collapse;font-size:12px}
    .n3-audit-table th,.n3-audit-table td{padding:12px 10px;border-bottom:1px solid #234256;text-align:left;vertical-align:middle}
    .n3-audit-table th{color:#91b4d0}.n3-audit-positive{color:#14d39a}.n3-audit-negative{color:#ff6579}.n3-audit-warning{color:#fbbf24}
    .n3-audit-pager{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-top:16px;font-size:12px}
    .n3-audit-detail{background:#061826;border:1px solid #315675;border-radius:9px;padding:16px;margin-top:18px;overflow-wrap:anywhere}
    .n3-audit-detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px;margin-top:12px}
    .n3-audit-field{border:1px solid #21465f;padding:10px;border-radius:7px;min-width:0}
    .n3-audit-field small{display:block;color:#91b4d0;margin-bottom:5px}.n3-audit-field strong{font-size:12px}
    .n3-audit-note{color:#91b4d0;font-size:12px;margin-top:12px}
    `;

    function createView() {
        const view = make('section', undefined, 'n3-audit-view');
        view.id = 'n3-journal-view';
        view.hidden = true;
        view.innerHTML = `
          <div class="n3-audit-title">
            <div><h2>Journal &amp; Audit</h2><p class="n3-audit-muted">Read-only verification and modification evidence from saved N3 reports</p></div>
            <button id="n3-audit-refresh" class="n3-audit-button" type="button">Refresh</button>
          </div>
          <div class="n3-audit-cards" id="n3-audit-stats"></div>
          <div class="n3-audit-controls">
            <label>Journal status<select id="n3-audit-status">
              <option value="">All</option>
              <option value="AUTHORIZED_MATCH">AUTHORIZED_MATCH</option>
              <option value="UNJOURNALED_CHANGE">UNJOURNALED_CHANGE</option>
              <option value="UNREGISTERED_CARD">UNREGISTERED_CARD</option>
              <option value="NOT_EVALUATED">NOT_EVALUATED</option>
            </select></label>
            <label>Card UID / family<input id="n3-audit-search" type="search" placeholder="UID or NTAG215"></label>
            <button id="n3-audit-search-btn" class="n3-audit-button" type="button">Search</button>
          </div>
          <p id="n3-audit-message" class="n3-audit-muted" role="status">Loading...</p>
          <div class="n3-audit-scroll"><table class="n3-audit-table"><thead><tr>
            <th>Verification time</th><th>Card family</th><th>UID</th><th>Verdict</th>
            <th>Journal status</th><th>Rollback</th><th>Baseline</th><th>Details</th>
          </tr></thead><tbody id="n3-audit-rows"></tbody></table></div>
          <div class="n3-audit-pager">
            <button id="n3-audit-prev" class="n3-audit-button" type="button">Previous</button>
            <span id="n3-audit-page"></span>
            <button id="n3-audit-next" class="n3-audit-button" type="button">Next</button>
          </div>
          <section id="n3-audit-detail" class="n3-audit-detail" hidden></section>
          <p class="n3-audit-note">Audit entries are reconstructed from verification reports; this page does not prove an immutable audit trail or the exact time a card was externally modified.</p>
        `;
        return view;
    }

    function addCard(parent, label, value) {
        const box = make('div', undefined, 'n3-audit-card');
        box.appendChild(make('span', label));
        box.appendChild(make('strong', value));
        parent.appendChild(box);
    }

    function renderStats(data) {
        const container = el('n3-audit-stats');
        container.replaceChildren();
        const statuses = data.journal_status_counts || {};
        const verdicts = data.verdict_counts || {};
        addCard(container, 'Total saved reports', data.all_report_count || 0);
        addCard(container, 'Authorized matches', statuses.AUTHORIZED_MATCH || 0);
        addCard(container, 'Unjournaled changes', statuses.UNJOURNALED_CHANGE || 0);
        addCard(container, 'Modified verdicts', verdicts.MODIFIED || 0);
    }

    function addCell(row, value, cls) {
        const td = make('td', value);
        if (cls) td.className = cls;
        row.appendChild(td);
        return td;
    }

    function verdictClass(value) {
        if (value === 'VALID') return 'n3-audit-positive';
        if (value === 'MODIFIED') return 'n3-audit-negative';
        return 'n3-audit-warning';
    }

    function renderRows(data) {
        const body = el('n3-audit-rows');
        body.replaceChildren();
        total = Number(data.total) || 0;
        hasMore = Boolean(data.has_more);
        const rows = Array.isArray(data.events) ? data.events : [];
        if (!rows.length) {
            const tr = document.createElement('tr');
            const td = addCell(tr, 'No saved evidence for this filter.');
            td.colSpan = 8;
            body.appendChild(tr);
        }
        for (const entry of rows) {
            const tr = document.createElement('tr');
            addCell(tr, dateText(entry.verification_time_utc));
            addCell(tr, safeText(entry.card_family));
            addCell(tr, safeText(entry.uid));
            addCell(tr, safeText(entry.verdict), verdictClass(entry.verdict));
            addCell(tr, safeText(entry.journal_status));
            addCell(tr, entry.rollback_detected === true ? 'YES' : entry.rollback_detected === false ? 'NO' : '--');
            addCell(tr, entry.baseline_version_used != null ? `V${entry.baseline_version_used}` : '--');
            const action = document.createElement('td');
            const button = make('button', 'View evidence', 'n3-audit-button');
            button.type = 'button';
            button.disabled = !entry.scan_id;
            button.addEventListener('click', () => showDetail(entry.scan_id));
            action.appendChild(button);
            tr.appendChild(action);
            body.appendChild(tr);
        }
        el('n3-audit-page').textContent = `Matching: ${total} · Page ${Math.floor(offset / PER_PAGE) + 1} · Loaded: ${rows.length}`;
        el('n3-audit-prev').disabled = offset === 0;
        el('n3-audit-next').disabled = !hasMore;
    }

    async function loadEvents() {
        if (loading) return;
        loading = true;
        const thisRequest = ++requestId;
        el('n3-audit-refresh').disabled = true;
        el('n3-audit-message').textContent = 'Loading journal evidence...';
        const query = new URLSearchParams({ limit: PER_PAGE, offset });
        const status = el('n3-audit-status').value;
        const search = el('n3-audit-search').value.trim();
        if (status) query.set('status', status);
        if (search) query.set('q', search);
        try {
            const response = await fetch(`${API}?${query.toString()}`, { cache: 'no-store' });
            if (!response.ok) throw new Error(`HTTP ${response.status}. Check the installed Flask backend.`);
            const data = await response.json();
            if (data.status !== 'OK' || !Array.isArray(data.events)) throw new Error('Unexpected API response');
            if (thisRequest !== requestId) return;
            renderStats(data);
            renderRows(data);
            el('n3-audit-message').textContent = `Report-derived audit: ${data.events.length} entries shown. ` +
                (data.skipped_invalid_reports ? `${data.skipped_invalid_reports} invalid reports skipped.` : '');
        } catch (error) {
            el('n3-audit-message').textContent = `Could not load journal: ${error.message}`;
        } finally {
            if (thisRequest === requestId) el('n3-audit-refresh').disabled = false;
            loading = false;
        }
    }

    function field(parent, label, value) {
        const wrapper = make('div', undefined, 'n3-audit-field');
        wrapper.appendChild(make('small', label));
        wrapper.appendChild(make('strong', Array.isArray(value) ? value.join(', ') || '--' : safeText(value)));
        parent.appendChild(wrapper);
    }

    async function showDetail(scanId) {
        const container = el('n3-audit-detail');
        container.hidden = false;
        container.textContent = 'Loading selected audit evidence...';
        try {
            const response = await fetch(`${API}/${encodeURIComponent(scanId)}`, { cache: 'no-store' });
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const result = await response.json();
            if (!result.event) throw new Error('No event in response');
            const item = result.event;
            const time = item.time_evidence || {};
            container.replaceChildren();
            const top = make('div', undefined, 'n3-audit-title');
            top.appendChild(make('h3', 'Selected Journal & Audit Evidence'));
            const close = make('button', 'Close details', 'n3-audit-button');
            close.type = 'button';
            close.addEventListener('click', () => { container.hidden = true; });
            top.appendChild(close);
            container.appendChild(top);
            const grid = make('div', undefined, 'n3-audit-detail-grid');
            field(grid, 'Scan ID', item.scan_id);
            field(grid, 'Card / UID', `${safeText(item.card_family)} · ${safeText(item.uid)}`);
            field(grid, 'Verdict', item.verdict);
            field(grid, 'Journal Status', item.journal_status);
            field(grid, 'Journal Reason', item.journal_reason);
            field(grid, 'Rollback Detected', item.rollback_detected === true ? 'YES' : item.rollback_detected === false ? 'NO' : '--');
            field(grid, 'Rollback Status', item.rollback_status);
            field(grid, 'Matched Older Version', item.matched_older_version == null ? '--' : `V${item.matched_older_version}`);
            field(grid, 'Baseline Used', item.baseline_version_used == null ? '--' : `V${item.baseline_version_used}`);
            field(grid, 'Latest Authorized Baseline', item.latest_authorized_version == null ? '--' : `V${item.latest_authorized_version}`);
            field(grid, 'Application / NDEF', item.application_status);
            field(grid, 'Raw Memory', item.raw_memory_status);
            field(grid, 'Security State', item.security_status);
            field(grid, 'Tamper Classification', item.tamper_classification);
            field(grid, 'Time Evidence Status', time.status);
            field(grid, 'Last Known Valid', dateText(time.last_known_valid_utc));
            field(grid, 'First Detected Modified', dateText(time.first_detected_modified_utc));
            field(grid, 'Modification Window Start', dateText(time.possible_window_start_utc));
            field(grid, 'Modification Window End', dateText(time.possible_window_end_utc));
            field(grid, 'Exact Modification Time', dateText(time.exact_modification_time_utc));
            field(grid, 'Time Reason', time.reason);
            field(grid, 'Verification Time', dateText(item.verification_time_utc));
            container.appendChild(grid);
            if (Array.isArray(item.changed_locations) && item.changed_locations.length) {
                const locations = item.changed_locations.map(x => `${x.unit} ${safeText(x.number)} (${safeText(x.region)})`).join(' · ');
                container.appendChild(make('p', `Changed memory locations: ${locations}`, 'n3-audit-note'));
            }
        } catch (error) {
            container.textContent = `Unable to load selected evidence: ${error.message}`;
        }
    }

    function init() {
        const main = document.querySelector('.main-content');
        const nav = [...document.querySelectorAll('.sidebar-nav .nav-item')];
        const journalBtn = nav.find(x => x.textContent.replace(/\s+/g, ' ').trim().toLowerCase() === 'journal & audit');
        if (!main || !journalBtn) {
            console.error('N3 Journal & Audit: missing .main-content or sidebar button');
            return;
        }
        const style = make('style');
        style.textContent = css;
        document.head.appendChild(style);
        const view = createView();
        main.appendChild(view);

        // Existing dashboard/history/baseline handlers remain untouched.
        // Restore visibility BEFORE their click handlers run on navigation away.
        function leaveJournal() {
            if (!restoreVisibility) return;
            for (const [child, wasHidden] of restoreVisibility) {
                child.hidden = wasHidden;
            }
            restoreVisibility = null;
            view.hidden = true;
            journalBtn.classList.remove('active');
        }
        for (const other of nav) {
            if (other !== journalBtn) {
                other.addEventListener('click', leaveJournal, { capture: true });
            }
        }
        journalBtn.disabled = false; // history.js may have disabled unfinished sections
        journalBtn.removeAttribute('title');
        journalBtn.addEventListener('click', () => {
            if (!restoreVisibility) {
                restoreVisibility = new Map([...main.children]
                    .filter(c => c !== view)
                    .map(c => [c, c.hidden]));
            }
            [...main.children].forEach(child => {
                if (child !== view && !child.classList.contains('top-header')) child.hidden = true;
            });
            view.hidden = false;
            nav.forEach(button => button.classList.toggle('active', button === journalBtn));
            loadEvents();
        });
        el('n3-audit-refresh').addEventListener('click', loadEvents);
        el('n3-audit-search-btn').addEventListener('click', () => { offset = 0; loadEvents(); });
        el('n3-audit-status').addEventListener('change', () => { offset = 0; loadEvents(); });
        el('n3-audit-search').addEventListener('keydown', (event) => {
            if (event.key === 'Enter') { offset = 0; loadEvents(); }
        });
        el('n3-audit-prev').addEventListener('click', () => {
            offset = Math.max(0, offset - PER_PAGE);
            el('n3-audit-detail').hidden = true;
            loadEvents();
        });
        el('n3-audit-next').addEventListener('click', () => {
            if (!hasMore) return;
            offset += PER_PAGE;
            el('n3-audit-detail').hidden = true;
            loadEvents();
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
