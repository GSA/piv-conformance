#!/usr/bin/env python3
"""Verify candidate traceability and record separate evidence-lane metrics.

Run the documented Gradle lanes first. This checks consistency and preservation;
it cannot turn a partial manifest into a complete normative denominator.
"""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
def read(name): return json.loads((ROOT/'standards'/name).read_text())
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def count(items): return dict(sorted(collections.Counter(items).items()))

baseline = read('baseline.json')
for name, expected in baseline['database_sha256'].items():
    assert digest(ROOT/name) == expected, 'Historical DB changed: '+name
fixture = ROOT/'cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/MANIFEST.sha256'
assert digest(fixture) == baseline['fixture_manifest_sha256'], 'Historical fixture manifest changed'
changed = set(subprocess.check_output(['git','diff','--name-only',baseline['engineering_pr_head']],cwd=ROOT,text=True).splitlines())
assert not changed.intersection(baseline['packaging_files']), 'Packaging changes mixed into standards work'
for module in ('cardlib','conformancelib','tools/85b-swing-gui'):
    assert 'gradle-8.14.5-' in (ROOT/module/'gradle/wrapper/gradle-wrapper.properties').read_text()
    assert (ROOT/module/'src/main/resources/build.version').read_text().strip() == '1.0.7'
java = subprocess.check_output([str(Path(os.environ['JAVA_HOME'])/'bin/java'),'--version'],text=True)
assert java.startswith('openjdk 17.'), 'Evidence must use Java 17'

manifest = read('current-manifest.json')
assert manifest['atomic_denominator'] is None and manifest['release_state']=='INCOMPLETE'
rules = {r['rule_id']:r for r in manifest['requirements']}
assert len(rules)==len(manifest['requirements'])
vectors = {}
families = {}
for family, class_name in [('data-model','CurrentDataModelEvidenceTest'),('crypto','CurrentCryptoEvidenceTest'),('linked','CurrentLinkedEvidenceTest')]:
    selected = read(family+'-vectors.json')
    tsv = ROOT/f'conformancelib/src/main/resources/standards/current-{family}.tsv'
    encoded = [line.split('\t') for line in tsv.read_text().splitlines() if line and not line.startswith('#')]
    assert encoded == [[v['id'],v['method'],v['expected'],v['input_hex']] for v in selected]
    report = ET.parse(ROOT/f'conformancelib/build/test-results/currentCandidateTest/TEST-gov.gsa.pivconformance.conformancelib.tests.{class_name}.xml').getroot()
    tested = {t.attrib['name']:t for t in report.findall('testcase')}
    for vector in selected:
        assert vector['id'] not in vectors, 'Duplicate fixture id'
        assert hashlib.sha256(bytes.fromhex(vector['input_hex'])).hexdigest()==vector['sha256']
        case = tested[vector['id']]
        assert case.find('failure') is None and case.find('error') is None and case.find('skipped') is None
        vectors[vector['id']] = vector
    families[family] = dict(distinct_vectors=len(selected),expected_outcomes=count('PASS' if v['expected']=='PASS' else 'FAIL' for v in selected),
                            kinds=count(v['kind'] for v in selected),tsv_sha256=digest(tsv))
for rule in rules.values():
    for field in ('fixture_ids','positive_vector','negative_vector','boundary_vector','malformed_vector'):
        for id in rule[field]:
            vector = vectors[id]
            assert rule['rule_id'] in vector['requirements'], (rule['rule_id'],id)
            if field=='positive_vector': assert vector['expected']=='PASS'
            if field=='negative_vector': assert vector['expected']==rule['rule_id'], 'Wrong assertion credited'
    assert rule['test_quality']<=3, 'No complete atomic/independent proof is claimed in this snapshot'
    if rule.get('java_method'):
        source = ROOT/('conformancelib/src/main/java/'+rule['java_class'].replace('.','/')+'.java')
        assert 'void '+rule['java_method']+'(' in source.read_text()

db_path = ROOT/'conformancelib/build/standards/CURRENT_2026_CANDIDATE.db'
with sqlite3.connect('file:'+str(db_path)+'?mode=ro',uri=True) as db:
    db_rows = db.execute('SELECT count(*) FROM TestCases').fetchone()[0]
    assert db_rows==35
    assert db.execute('SELECT Profile,Readiness FROM StandardsProfile').fetchone()==('CURRENT_2026_CANDIDATE','NOT_YET_READY')
    mappings=[dict(case_id=r[0],method=r[1],container=r[2]) for r in db.execute('SELECT c.TestCaseIdentifier,s.Method,c.TestCaseContainer FROM TestCases c JOIN TestsToSteps l ON l.TestId=c.Id JOIN TestSteps s ON s.Id=l.TestStepId ORDER BY c.Id')]

lanes = {}
lane_specs = [('engineering_cardlib','cardlib','test',446,0),('engineering_conformance','conformancelib','test',11,0),
              ('engineering_swing','tools/85b-swing-gui','test',12,0),
              ('current_candidate','conformancelib','currentCandidateTest',len(vectors)+len(read('data-model-vectors.json'))+db_rows,0),
              ('synthetic_certificates','conformancelib','certificateFixtureTest',75,0),
              ('existing_cct_sun','conformancelib','existingCctRegressionTest',36,0),
              ('existing_cct_bc','conformancelib','existingCctRegressionBcTest',36,0),
              ('historical_external_certificates','conformancelib','historicalCertificateFixtureTest',24,24)]
for name,module,task,expected_tests,expected_failures in lane_specs:
    files=sorted((ROOT/module/'build/test-results'/task).glob('TEST-*.xml'))
    assert files, 'Run '+module+':'+task
    roots=[ET.parse(f).getroot() for f in files]
    result={k:sum(int(r.get(k,0)) for r in roots) for k in ('tests','failures','errors','skipped')}
    assert result==dict(tests=expected_tests,failures=expected_failures,errors=0,skipped=0), (name,result)
    if expected_failures:
        assert all('Unable to open explicit external file' in f.get('message','') for r in roots for f in r.findall('.//failure'))
    result['reports']=[dict(path=str(f.relative_to(ROOT)),sha256=digest(f)) for f in files]
    lanes[name]=result

by_publication={}
for document in sorted({r['normative_document'] for r in rules.values()}):
    selected=[r for r in rules.values() if r['normative_document']==document]
    by_publication[document]=dict(atomic_applicable_denominator=None,
        rule_groups_with_assertions=sum(bool(r.get('java_method')) for r in selected),
        aggregate_gap_or_scope_records=sum(not r.get('java_method') for r in selected),
        disposition=count(r['implementation_status'] for r in selected),quality=count(r['test_quality'] for r in selected))
inputs=[ROOT/'standards/current-manifest.json',ROOT/'conformancelib/build.gradle']
inputs+=sorted((ROOT/'conformancelib/src/main/java/gov/gsa/pivconformance/conformancelib/utilities').glob('Current*.java'))
inputs+=sorted((ROOT/'conformancelib/src/main/java/gov/gsa/pivconformance/conformancelib/tests').glob('Current*.java'))
inputs += [ROOT/'conformancelib/src/main/java/gov/gsa/pivconformance/conformancelib/tests'/name for name in
           ('ExistingCctRegressionTest.java','PKIX_X509DataObjectTests.java','SP800_78_X509DataObjectTests.java')]
metrics=dict(recorded_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),profile='CURRENT_2026_CANDIDATE',
    verdict='NOT_YET_READY',java_runtime=java.strip(),atomic_denominator=None,
    denominator_reason=manifest['denominator_status'],by_publication=by_publication,
    quality_rule_groups_including_gap_records=count(r['test_quality'] for r in rules.values()),
    delta_rule_groups=count(r.get('delta','UNREVIEWED_AGGREGATE') for r in rules.values()),
    distinct_synthetic_vectors=len(vectors),vector_families=families,candidate_database=dict(rows=db_rows,sha256=digest(db_path),mappings=mappings),
    lanes=lanes,historical_conformance_execution='NOT_RUN (hardware/profile-level atoms are not the 462 engineering tests)',
    physical_hardware='NOT_RUN',piv_i_current_applicability='UNRESOLVED; historical databases preserved',
    protected_databases_and_fixture_manifest='UNCHANGED',packaging_files='UNCHANGED relative to reviewed engineering_pr_head',
    evidence_inputs=[dict(path=str(p.relative_to(ROOT)),sha256=digest(p)) for p in inputs],
    warnings=['Rule groups, source locators, DB rows and JUnit invocations are different units',
              f'Only the direct distinct-vector count is {len(vectors)}; entry-point tests repeat data vectors and separately check absence',
              'No complete atomic normative denominator or standards-coverage percentage is established'])
(ROOT/'standards/metrics.json').write_text(json.dumps(metrics,indent=2)+'\n')
print('Verified preserved baseline, fixture hashes, assertion-specific negative links and separate lanes.')
print(json.dumps({name:{k:v for k,v in r.items() if k!='reports'} for name,r in lanes.items()},indent=2))
