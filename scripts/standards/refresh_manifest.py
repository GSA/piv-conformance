#!/usr/bin/env python3
"""Refresh evidence links from the pinned vector catalogues; never infer coverage.

Failure evidence belongs only to the rule actually reported by the assertion.
Sharing an input with another assertion is not proof that assertion rejects it.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
path = ROOT / 'standards/current-manifest.json'
manifest = json.loads(path.read_text())
vectors = [v for name in ('data-model', 'crypto', 'linked')
           for v in json.loads((ROOT / f'standards/{name}-vectors.json').read_text())]
cases = json.loads((ROOT / 'build/standards/historical-cases.json').read_text())
for rule in manifest['requirements']:
    # Detailed database rows belong to the generated historical inventory.
    rule.pop('affected_db_rows', None)
    if not rule.get('java_method'):
        # Missing fields stay explicitly unknown; an aggregate gap is not an atom.
        for field in ('java_class','java_method','container','table_or_row','normative_strength',
                      'document_revision','expected_result'):
            rule.setdefault(field,None)
        for field in ('historical_cct_test_ids','fixture_ids','positive_vector',
                      'negative_vector','boundary_vector','malformed_vector'):
            rule.setdefault(field,[])
        rule.setdefault('applicability','Aggregate scope/gap record; atomic applicability review pending')
        rule.setdefault('hardware_scope',rule['implementation_status']=='HARDWARE_OWNED')
        rule.setdefault('notes','Excluded from any claim of an atomic denominator or measured normative coverage')
        continue
    selected = [v for v in vectors if rule['rule_id'] in v['requirements']
                and v['expected'] in ('PASS', rule['rule_id'])]
    rule['fixture_ids'] = [v['id'] for v in selected]
    rule['positive_vector'] = [v['id'] for v in selected if v['expected'] == 'PASS']
    rule['negative_vector'] = [v['id'] for v in selected if v['expected'] != 'PASS']
    for kind in ('boundary', 'malformed'):
        rule[kind + '_vector'] = [v['id'] for v in selected if v['kind'] == kind]
    rule['test_quality'] = 3 if rule['negative_vector'] else 2 if rule['positive_vector'] else 1
    rule['applicability'] = 'Present ' + rule['container'] + ' object; candidate PIV only'
    rule['expected_result'] = dict(PASS=rule['requirement'], FAIL='Violation of ' + rule['rule_id'],
                                   setup_error='Not normative evidence')
    if rule['rule_id'] in ('73-UUID-CERT-LINK', '76-CBEFF-HEADER'):
        methods = {'PKIX_Test_27'} if rule['rule_id'] == '73-UUID-CERT-LINK' else {
            i['java_method'] for c in cases for i in c['implementations']
            if 'SP800_76' in i['java_class']}
        linked = [c for c in cases if any(i['java_method'] in methods for i in c['implementations'])]
        rule['historical_cct_test_ids'] = sorted({c['cct_test_id'] for c in linked})
        rule['historical_mapping_precision'] = 'Family association; not atomic behavior equivalence'
    if rule['rule_id'] == '73-UUID-CERT-LINK':
        rule['applicability'] = 'PIV Authentication and Card Authentication certificates; CHUID card UUID present'
    if rule['rule_id'] == '76-CBEFF-HEADER':
        rule['applicability'] = 'Mandatory on-card fingerprint CBEFF; does not cover enrollment images, face, iris or OCC'
    if rule['rule_id'] in ('73-KEY-HISTORY', '78-RSA-EXPONENT'):
        rule['delta'] = 'UNCHANGED'
        rule['notes'] += ' New candidate assertions for existing requirements; NEW implementation is not a NEW normative requirement.' if 'NEW implementation' not in rule['notes'] else ''
    rule['negative_evidence_policy'] = 'Only failures reporting this exact rule ID count; setup/parser failures with other IDs do not.'
manifest['requirements'] = manifest['requirements']
path.write_text(json.dumps(manifest, indent=2) + '\n')
