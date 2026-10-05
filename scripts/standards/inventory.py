#!/usr/bin/env python3
"""Reproduce the historical inventory without opening a card or changing a database.

This is a source index, not a semantic proof. Unknown evidence remains null and
source-only assertion counts never receive quality > 1. Run from any directory.
"""
import collections
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build' / 'standards'
BASE = '90f754d785f7fe4ca9fb19e1c66102da0608447d'


def historical(path):
    return subprocess.check_output(['git', 'show', f'{BASE}:{path}'], cwd=ROOT)


def mask(text, strings=False):
    pattern = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    def replace(m):
        if not strings and not m[0].startswith('/'):
            return m[0]
        return ''.join('\n' if c == '\n' else ' ' for c in m[0])
    return re.sub(pattern, replace, text)


def methods(path, source):
    clean = mask(source)
    structural = mask(source, True)
    package = re.search(r'package\s+([\w.]+);', clean)[1]
    found = []
    # Test atoms are void methods. Helper calls remain visible in source_body.
    for match in re.finditer(r'\bvoid\s+(\w+)\s*\([^;{}]*\)\s*(?:throws\s+[^{}]+)?\{', structural):
        start = match.end()
        end, depth = start, 1
        while depth and end < len(structural):
            depth += (structural[end] == '{') - (structural[end] == '}')
            end += 1
        body = clean[start:end-1]
        assertions = []
        for a in re.finditer(r'\b(?:assert\w+|fail|assume\w+)\s*\(', mask(body, True)):
            i, level = a.end(), 1
            structure = mask(body, True)
            while i < len(body) and level:
                level += (structure[i] == '(') - (structure[i] == ')')
                i += 1
            assertions.append(' '.join(body[a.start():i].split()))
        state = 'UNREVIEWED'  # Assertion counts do not establish semantic coverage.
        if re.fullmatch(r'\s*(?:return\s*;)?\s*', body): state = 'UNCONDITIONAL_PASS'
        if 'not implemented' in body: state = 'PLACEHOLDER'
        risks = []
        if state == 'UNCONDITIONAL_PASS': risks.append('Returns normally without an assertion')
        if 'catch' in body: risks.append('Review exception paths for swallowed failures')
        if re.search(r'assertTrue\s*\(\s*true|\.length\s*>=\s*0', body): risks.append('Tautological assertion')
        if re.search(r'\breturn\s*;', body): risks.append('Early return: applicability/assertion dominance needs review')
        found.append(dict(java_class=package+'.'+path.stem, java_method=match[1],
                          source_path=str(path), source_line=source[:match.start()].count('\n')+1,
                          source_body=source[start:end-1].strip(), actual_assertions=assertions,
                          implementation_status=state, test_quality=int(bool(assertions) and state != 'PLACEHOLDER'),
                          pass_without_requirement_evaluation=True if state == 'UNCONDITIONAL_PASS' else None,
                          false_pass_risk=risks or ['Semantic review and independent negative evidence pending'],
                          false_fail_risk=['Semantic review and independent positive evidence pending'],
                          physical_hardware_dependency=True if re.search(r'APDU|transmit|CardChannel|selectApplication|AtomHelper\.(getDataObject|isOptionalAndAbsent)|CardInfoController', body) else None,
                          certificate_fixture_dependency='EXTERNAL_CORPUS' if path.stem == 'ValidatorTest' and 'testIsValid' in match[1] else 'CARD_CERTIFICATE_OR_CMS' if re.search(r'Certificate|CMS|Signer', body) else None,
                          nist_interpretation_needed=None))
    return found


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    paths = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', BASE,
                                    'conformancelib/src/main/java'], cwd=ROOT, text=True).splitlines()
    atoms = []
    for path in paths:
        if '/tests/' in path and path.endswith('.java'):
            atoms.extend(methods(Path(path), historical(path).decode()))
    lookup = {(m['java_class'],m['java_method']): m for m in atoms}
    findings = json.loads((ROOT/'standards/historical-findings.json').read_text())
    for finding in findings:
        for atom in atoms:
            if atom['java_class'].endswith('.'+finding.get('java_class','')) and atom['java_method'] in finding.get('java_methods',[]):
                atom.setdefault('review_findings',[]).append(finding['id'])
                atom['implementation_status'] = finding.get('implementation_status', atom['implementation_status'])
                atom['false_pass_risk'].extend(finding.get('false_pass_risk',[]))
                atom['false_fail_risk'].extend(finding.get('false_fail_risk',[]))
                atom['normative_scope'] = finding.get('scope','PART_1_DATA_MODEL')
                if 'pass_without_requirement_evaluation' in finding:
                    atom['pass_without_requirement_evaluation'] = finding['pass_without_requirement_evaluation']
    inventory, steps, summaries = [], [], {}
    for path in sorted((ROOT/'conformancelib/testdata').glob('*.db')):
        rel = str(path.relative_to(ROOT))
        # Query an in-memory copy of the protected commit, even after candidate edits.
        db = sqlite3.connect(':memory:')
        db.deserialize(historical(rel))
        db.row_factory = sqlite3.Row
        step_rows = {r['Id']:dict(r) for r in db.execute('SELECT * FROM TestSteps')}
        used = set()
        for row in db.execute('SELECT * FROM TestCases ORDER BY Id'):
            row = dict(row)
            links = [dict(r) for r in db.execute('SELECT * FROM TestsToSteps WHERE TestId=? ORDER BY ExecutionOrder,Id',(row['Id'],))]
            implementations = []
            for link in links:
                s = step_rows[link['TestStepId']]
                used.add(s['Id'])
                m = lookup.get((s['Class'],s['Method']))
                implementations.append(dict(step_id=s['Id'], link=link, atom=s['Description'],
                    java_class=s['Class'], java_method=s['Method'],
                    implementation_status=m['implementation_status'] if m else 'MISSING',
                    test_quality=m['test_quality'] if m else 0,
                    parameters=[dict(p) for p in db.execute('SELECT * FROM TestStepParameters WHERE TestStepId=? AND (TestId IS NULL OR TestId=?) ORDER BY ParamOrder,Id',(s['Id'],row['Id']))]))
            inventory.append(dict(database=rel, database_row_id=row['Id'], cct_test_id=row['TestCaseIdentifier'],
                profile='PIV-I' if 'PIV-I' in path.name else 'PIV',
                standards_profile='HISTORICAL_CCT', enabled=row['Enabled']==1,
                outline_only=not links, description=row['TestCaseDescription'],container=row.get('TestCaseContainer'),
                stored_expected_status=row['ExpectedStatus'], implementations=implementations,
                execution_path='ConformanceTestDatabase.getTestCases -> TestCaseModel.retrieveForId -> ConformanceTestRunner (or GUI) -> JUnit selectMethod -> ParameterizedArgumentsProvider -> AtomHelper/CardInfoController' if links else 'TestCaseModel assigns TESTCATEGORY when no TestsToSteps rows exist',
                historical_source='Database description and source comments; 85B methodology only',
                historical_revision='Mixed historical revisions; exact binding pending', historical_section=None,
                current_normative_source=None,current_revision=None,current_section=None,current_table_or_row=None,
                normative_strength=None, applicability='Profile and container from this row; current applicability unreviewed',
                expected_pass_condition='All mapped assertions complete normally; compare ExpectedStatus in runner' if links else None,
                expected_fail_condition='Mapped assertion failure; setup failures are not normative evidence' if links else None,
                historical_fixture_input='Production: card data acquired by CardInfoController; ICAM: database describes expected card; parser fixture corpus is NOT proof of this atom',
                positive_vector=None,negative_vector=None,malformed_input_vector=None,boundary_vector=None,
                implementation_status='OUTLINE_ONLY' if not links else 'PARTIAL',
                test_quality=min((i['test_quality'] for i in implementations), default=0),
                nist_interpretation_needed=None))
            record = inventory[-1]
            mapped = [lookup[(i['java_class'],i['java_method'])] for i in implementations if (i['java_class'],i['java_method']) in lookup]
            record['actual_assertions'] = [a for m in mapped for a in m['actual_assertions']]
            record['review_findings'] = sorted({f for m in mapped for f in m.get('review_findings',[])})
            record['physical_hardware_dependency'] = True if any(m['physical_hardware_dependency'] is True for m in mapped) else None
            record['certificate_fixture_dependency'] = sorted({m['certificate_fixture_dependency'] for m in mapped if m['certificate_fixture_dependency']})
            record['false_pass_risk'] = sorted({s for m in mapped for s in m['false_pass_risk']})
            record['false_fail_risk'] = sorted({s for m in mapped for s in m['false_fail_risk']})
            record['pass_without_requirement_evaluation'] = True if mapped and all(m['pass_without_requirement_evaluation'] is True for m in mapped) else None
            record['normative_scope'] = sorted({m.get('normative_scope','REVIEW_PENDING') for m in mapped})
            if mapped and len({m['implementation_status'] for m in mapped}) == 1:
                record['implementation_status'] = mapped[0]['implementation_status']
        for s in step_rows.values():
            steps.append(dict(database=rel, database_step=s, referenced_by_case=s['Id'] in used,
                              method_resolved=(s['Class'],s['Method']) in lookup))
        selected = [r for r in inventory if r['database']==rel]
        summaries[rel] = dict(rows=len(selected), enabled=sum(r['enabled'] for r in selected),
            executable_rows=sum(not r['outline_only'] for r in selected), outline_rows=sum(r['outline_only'] for r in selected),
            step_definitions=len(step_rows), referenced_steps=len(used),
            unique_referenced_methods=len({(i['java_class'],i['java_method']) for r in selected for i in r['implementations']}))
    refs={(i['java_class'],i['java_method']) for r in inventory for i in r['implementations']}
    for atom in atoms: atom['referenced_by_database']=(atom['java_class'],atom['java_method']) in refs
    for name, data in [('historical-cases',inventory),('historical-steps',steps),('historical-methods',atoms),
                       ('historical-summary',dict(source_commit=BASE,databases=summaries,
                         source_methods=len(atoms), unique_referenced_methods=len(refs),
                         dispositions=dict(collections.Counter(m['implementation_status'] for m in atoms)),
                         quality=dict(collections.Counter(m['test_quality'] for m in atoms)),
                         semantic_review_complete=False, normative_coverage_denominator=None))]:
        (OUT/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps(summaries,indent=2))


if __name__ == '__main__':
    main()
