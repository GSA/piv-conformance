#!/usr/bin/env python3
"""Build an explicitly incomplete candidate database; never mutate historical DBs."""
from pathlib import Path
import hashlib
import json
import sqlite3

ROOT = Path(__file__).resolve().parents[2]
source = ROOT/'conformancelib/testdata/PIV_Production_Cards.db'
target = ROOT/'conformancelib/build/standards/CURRENT_2026_CANDIDATE.db'
target.parent.mkdir(parents=True,exist_ok=True)
baseline=json.loads((ROOT/'standards/baseline.json').read_text())
assert hashlib.sha256(source.read_bytes()).hexdigest()==baseline['database_sha256'][str(source.relative_to(ROOT))]
# Fresh database on each run, with the production schema and no historical tests.
if target.exists(): target.unlink()
src=sqlite3.connect('file:'+str(source)+'?mode=ro',uri=True)
db=sqlite3.connect(target)
for (sql,) in src.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
    db.execute(sql)
manifest=json.loads((ROOT/'standards/current-manifest.json').read_text())
groups={}
for rule in manifest['requirements']:
    if rule.get('java_method') and rule.get('implementation_status') in ('IMPLEMENTED','PARTIAL'):
        groups.setdefault((rule['java_method'],rule['container']),[]).append(rule['rule_id'])
for method in ('certificateObject','cardKey','certificateSignature','cardUuid'):
    key=(method,'X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID')
    if key in groups:
        groups[(method,'X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID')]=groups[key]
for index,((method,container),rules) in enumerate(sorted(groups.items()),1):
    description='CURRENT_2026_CANDIDATE / PARTIAL SCOPE: '+', '.join(rules)
    db.execute('INSERT INTO TestCases (Id,TestCaseIdentifier,TestCaseDescription,TestCaseContainer,Status,ExpectedStatus,Enabled) VALUES (?,?,?,?,NULL,1,1)',(index,'CANDIDATE.'+str(index),description,container))
    db.execute('INSERT INTO TestSteps (Id,Description,Class,Method,NumParameters) VALUES (?,?,?,?,0)',(index,description,'gov.gsa.pivconformance.conformancelib.tests.CurrentCandidateTests',method))
    db.execute('INSERT INTO TestsToSteps (TestStepId,TestId,ExecutionOrder) VALUES (?,?,0)',(index,index))
db.execute('CREATE TABLE StandardsProfile (Profile TEXT, Readiness TEXT, Scope TEXT)')
db.execute('INSERT INTO StandardsProfile VALUES (?,?,?)',('CURRENT_2026_CANDIDATE','NOT_YET_READY','Selected PIV data-model rules only; historical/PIV-I, Part 2 and Part 3 not included'))
db.commit()
print(target, 'executable rows:', len(groups))
