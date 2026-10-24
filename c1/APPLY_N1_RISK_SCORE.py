"""One-time, non-destructive installer for existing N1_Auto_Dashboard (panel or v2).

Run from N1 Implementation root: py APPLY_N1_RISK_SCORE.py
Creates timestamped backups of changed source files, does NOT alter NFC cards
or overwrite research datasets. No third-party libraries required.
"""
from __future__ import annotations
from pathlib import Path
import re
import shutil
from datetime import datetime

ROOT = Path(__file__).resolve().parent
DASH = ROOT / "N1_Auto_Dashboard"
MOD = Path(__file__).with_name("n1_scoring.py")
FILES = [DASH / "n1_dashboard.py", DASH / "dashboard.html"]
MARKER = "VIVA1_POLICY_INDEX_V1"

if not all(p.is_file() for p in FILES) or not MOD.is_file():
    raise SystemExit("ERROR: Put both patch files inside the N1 Implementation root, alongside N1_Auto_Dashboard")

backend = FILES[0].read_text(encoding="utf-8-sig")
html = FILES[1].read_text(encoding="utf-8-sig")
if MARKER in backend or MARKER in html:
    raise SystemExit("Score patch already installed. No files modified.")

# A guarded set of substitutions: refuse to modify an unfamiliar dashboard.
assert 'from n1_core import ' in backend, "Unknown Python dashboard layout"
assert 'self.card = None' in backend, "Unknown SharedState layout"
assert 'self.card = public_card(card)' in backend, "Unknown NFC accept handler"
assert '"card": self.card,' in backend, "Unknown API state JSON layout"
assert 'function update(state){latest=state;' in html, "Unknown JavaScript update function"
assert '<section class="panel scorepanel">' in html, "Unknown risk-card HTML layout"
assert '</style>' in html, "No HTML style section"
assert "const value = (id, x) =>" in html, "No JS value helper"

backend = re.sub(r'(?m)^(from n1_core import [^\n]+)$', r'\1\nfrom n1_scoring import score_card  # VIVA1_POLICY_INDEX_V1', backend, count=1)
backend = backend.replace('self.card = None', 'self.card = None\n        self.risk_score = None', 1)
backend = backend.replace('self.card = public_card(card)', 'self.card = public_card(card)\n            self.risk_score = score_card(card, text, kind)', 1)
backend = backend.replace('"card": self.card,', '"card": self.card,\n                "risk_score": self.risk_score,', 1)

new_section = '''<section class="panel scorepanel" aria-live="polite">
          <div class="sectionhead"><h3>Live NFC Risk Exposure Index</h3><span id="riskMode">PILOT • NOT COX</span></div>
          <div class="scoremain"><div class="scorecircle" id="pilotScore" style="font-size:33px">—</div>
            <div class="scorenote"><strong id="pilotBand">AWAITING NFC SCAN</strong><span id="pilotDescription">Read a supported tag to calculate the 0–100 rule-based security exposure index.</span></div></div>
          <div class="risk-breakdown" id="pilotBreakdown"></div>
          <div class="risk-coverage" id="pilotCoverage">Scoring is based on observed card configuration, not fabricated experiments.</div>
          <div class="footnotice">VIVA 1 PROTOTYPE — manually specified, explainable policy weights. The number is NOT an estimated attack probability, security certification, or validated Cox-regression risk. Final calibrated scoring belongs to Viva 2.</div>
        </section>'''
html, found = re.subn(r'<section class="panel scorepanel">.*?</section>', new_section, html, count=1, flags=re.S)
if found != 1:
    raise SystemExit("Cannot safely find existing scoring panel; no files changed")

styles = '''
/* VIVA1_POLICY_INDEX_V1: pilot numeric score and evidence breakdown */
.risk-breakdown{display:flex;flex-direction:column;gap:7px;margin:15px 0 8px}
.risk-factor{display:grid;grid-template-columns:1fr auto;gap:5px 12px;padding:10px;border:1px solid #304153;border-radius:10px;background:#0c1a2b;font-size:12px}
.risk-factor b{color:#7bedd0}.risk-factor .why{grid-column:1 / -1;color:#aebfd0;font-size:11px;line-height:1.4}
.risk-coverage{font-size:11px;color:#92afc0;margin:11px 0;overflow-wrap:anywhere}
'''
html = html.replace('</style>', styles + '</style>', 1)

js = r'''
// VIVA1_POLICY_INDEX_V1 - transparent read-only policy index, not Cox calibration.
function renderPilotScore(data){
  const list=$('pilotBreakdown'); list.replaceChildren();
  if(!data || data.score===null || data.score===undefined){
    value('pilotScore','—');value('pilotBand',data?.band||'AWAITING NFC SCAN');
    value('pilotDescription','Pilot numeric score unavailable: '+(data?.coverage||'Awaiting a supported scan'));
    value('pilotCoverage',data?.note||'Unknown properties are not assigned safe values.');
    value('riskMode','INSUFFICIENT EVIDENCE');return;
  }
  value('pilotScore',data.score+'/100');value('pilotBand',data.band+' EXPOSURE · T2 CONTEXT');
  value('riskMode','HEURISTIC • NOT COX');
  value('pilotDescription','0–100 preliminary configuration exposure index (not compromise likelihood).');
  value('pilotCoverage',data.coverage+' · '+data.note);
  for(const r of data.reasons||[]){
    const item=document.createElement('div');item.className='risk-factor';
    const a=document.createElement('span');a.textContent=r.factor;
    const b=document.createElement('b');b.textContent='+'+r.points+' pts';
    const note=document.createElement('div');note.className='why';
    note.textContent=r.observed+' — '+r.explanation;
    item.append(a,b,note);list.append(item);
  }
}
'''
html = html.replace('function update(state){latest=state;', js + '\nfunction update(state){latest=state;renderPilotScore(state.risk_score);', 1)
html = html.replace("'Score: NOT CALIBRATED'", "'Pilot exposure index: '+(latest.risk_score?.score==null?'UNAVAILABLE':latest.risk_score.score+'/100')+' (NOT Cox calibrated)'", 1)

# Prepare backup before updating. The current dashboard source is never discarded.
backup_dir = DASH / ("score_patch_backup_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
backup_dir.mkdir(parents=True, exist_ok=False)
for source in FILES:
    shutil.copy2(source, backup_dir / source.name)
module_target = DASH / "n1_scoring.py"
if module_target.exists():
    shutil.copy2(module_target, backup_dir / module_target.name)
try:
    FILES[0].write_text(backend, encoding="utf-8")
    FILES[1].write_text(html, encoding="utf-8")
    shutil.copy2(MOD, module_target)
except Exception:
    for source in FILES:
        shutil.copy2(backup_dir / source.name, source)
    raise
print("N1 VIVA-1 RISK SCORE PATCH: INSTALLED")
print("LIVE NFC FACTOR SCORING: ENABLED")
print("NTAG215 SCORING: SUPPORTED WHEN CONFIG PAGES CAPTURED")
print("MIFARE CLASSIC 1K: SUPPORTED WHEN READABLE KEY/BLOCK EVIDENCE EXISTS")
print("COX REGRESSION: NOT CALIBRATED")
print("ORIGINAL DASHBOARD BACKUP: CREATED")
print("NFC WRITE: NOT PERFORMED")
print("NEXT: restart dashboard and scan your NTAG215 card")
