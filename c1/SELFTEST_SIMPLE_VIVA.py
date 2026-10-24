from pathlib import Path
import tempfile,csv,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from n1_observed_score import score_known_card
with tempfile.TemporaryDirectory() as d:
    root=Path(d);(root/'Datasets').mkdir()
    with (root/'Datasets'/'configs.csv').open('w',encoding='utf-8',newline='') as f:
        fields=['card_instance','uid_writable','auth_type','default_key_present','lock_state','ndef_protection','cve_flag']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerow({
            'card_instance':'NTAG215_02','uid_writable':'Not writable','auth_type':'No authentication',
            'default_key_present':'Not Applicable','lock_state':'UNLOCKED','ndef_protection':'UNPROTECTED','cve_flag':'UNKNOWN'})
    r=score_known_card({'uid':'04 A3 C0 90 31 02 89'},root)
    assert r['score']==75.0,r
    assert r['coverage']==80.0,r
    assert r['known_applicable']==4 and r['applicable_total']==5,r
print('SELFTEST: PASSED')
print('NTAG215_02 EXAMPLE SCORE: 75/100')
print('EVIDENCE COVERAGE: 80%')
print('FINAL COX SCORE: PENDING')
