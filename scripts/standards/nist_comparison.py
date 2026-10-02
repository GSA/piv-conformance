#!/usr/bin/env python3
"""Index local NIST research evidence without copying or treating it as authority.

Usage: python3 scripts/standards/nist_comparison.py '/path/to/PIV Project Central'
Source/decompiler observations below were cross-checked against javap -p -c.
This is static comparison, not execution of the reference runner or equivalence proof.
"""
import collections
import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
research=Path(sys.argv[1])
analysis=research/'nist-piv-test-runner-5.0.1-analysis'
relative='PIV_TestRunner_modules-5.0.1/com/tvec/smart_card/piv/testscript/'
paths=[research/'cct-vs-nist-gap-analysis/data/nist-requirement-crosswalk.tsv',
       analysis/'metadata/requirements.tsv',analysis/'metadata/test-vectors.tsv']
for name in ('CertificateUtils','apdu/VerifyCertificateScriptItem','ScriptItemUtils'):
    paths += [analysis/'bytecode'/(relative+name+'.class'),analysis/'decompiled'/(relative+name+'.java')]
provenance=[dict(path=str(p.relative_to(research)),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in paths]
rows=list(csv.DictReader(paths[0].open(),delimiter='\t'))
crosswalk=[]
for r in rows:
    crosswalk.append(dict(reference_requirement=r['nist_requirement'],
        reference_subsystems=r['nist_subsystems'],historical_crosswalk=r['cct_classification'],
        historical_cct_test_ids=r['cct_matched_test_ids'],
        comparison='DIFFERENT_SCOPE' if r['cct_classification']=='cct_out_of_scope' else None,
        review_status='SCOPE_CLASSIFIED' if r['cct_classification']=='cct_out_of_scope' else 'BEHAVIOR_COMPARISON_PENDING'))
differences=[
 dict(id='NIST-RSA3072',classification='HISTORICAL_ONLY',reference_method='CertificateUtils.checkPublicKeySize',
      evidence='Bytecode offsets 61-114 accept EC256/384 or RSA2048 only',
      reference_behavior='Rejects RSA3072',candidate_behavior='Accepts active RSA3072 through 2030',
      authority='SP800-78-5 section 3.1 Table1',rules=['78-CARD-KEY'],fixtures=['rsa-bits-3072']),
 dict(id='NIST-RSA384',classification='SAME_REQUIREMENT_DIFFERENT_BEHAVIOR',reference_method='CertificateUtils.checkSignatureAlgorithm',
      evidence='Bytecode algorithm whitelist at offsets 0-75 has RSA_SHA1, RSA_SHA256, PSS, ECDSA_SHA256 and ECDSA_SHA384; no RSA_SHA384',
      reference_behavior='Rejects RSA SHA384 AlgorithmIdentifier',candidate_behavior='Accepts RSA SHA384 with NULL or absent parameters',
      authority='SP800-78-5 section 3.2.1 Table2; RFC4055',rules=['78-CERT-SIGNATURE'],fixtures=['rsa384-null','rsa384-absent']),
 dict(id='NIST-PSS384',classification='SAME_REQUIREMENT_DIFFERENT_BEHAVIOR',reference_method='CertificateUtils.checkSignatureAlgorithm',
      evidence='Bytecode/decompiled PSSParameterSpec digest comparison against SHA256 OID',
      reference_behavior='PSS branch only accepts the SHA256 digest comparison',candidate_behavior='Accepts SHA256 and SHA384 PSS digest identifiers',
      authority='SP800-78-5 section 3.2.1 Table2; RFC4055 sections 3 and 5',rules=['78-CERT-SIGNATURE'],fixtures=['pss-256','pss-384']),
 dict(id='NIST-LEGACY-SHA1',classification='HISTORICAL_ONLY',reference_method='CertificateUtils.checkSignatureAlgorithm',
      evidence='Bytecode/decompiled expiration cutoff branch uses December31 2010 for RSA SHA1',
      reference_behavior='Legacy SHA1 path has a historical expiration cutoff',candidate_behavior='Active current issuance assertion rejects SHA1; no blanket verdict on archived signatures',
      authority='SP800-78-5 section 3.2.1; current active-certificate scope',rules=['78-CERT-SIGNATURE'],fixtures=['signature-sha1']),
 dict(id='NIST-UUID-HISTORICAL-CCT',classification='SAME_REQUIREMENT_DIFFERENT_BEHAVIOR',reference_method='VerifyCertificateScriptItem.checkFASCNAndUUID; ScriptItemUtils.compareUuid',
      evidence='VerifyCertificateScriptItem bytecode offset183 compares URI with CHUID GUID; ScriptItemUtils compares two normalized strings',
      reference_behavior='Compares against CHUID GUID',candidate_behavior='Candidate also compares CHUID bytes; historical PKIX.matchUuid ignored its identifier argument',
      authority='SP800-73-5 Part1 section 3.4.1 item4',rules=['73-UUID-CERT-LINK'],fixtures=['uuid-link-mismatch']),
 dict(id='NIST-UUID-SYNTAX',classification='SAME_REQUIREMENT_DIFFERENT_BEHAVIOR',reference_method='ScriptItemUtils.normalizeUuid(String)',
      evidence='Bytecode calls toLowerCase and replaces all hyphens, urn: and uuid: before equality',
      reference_behavior='Normalization can accept a UUID string without the RFC4122 URN prefix or canonical hyphens',
      candidate_behavior='Requires urn:uuid: and canonical hexadecimal groups before comparing bytes',
      authority='SP800-73-5 Part1 section3.4.1 item4; RFC4122 section3',rules=['73-UUID-CERT-LINK'],fixtures=['uuid-link-no-hyphens','uuid-link-bare'])
]
data=dict(reference_version='NIST PIV Test Runner 5.0.1 (20200212-0308)',
    reference_authority='Historical comparison only; final NIST publications control candidate behavior',
    reference_installer_sha256='7e92b7ef0011574ae48bb984a87441fcddc78a2d8d04f31daae304a275cbaf99',
    evidence_level='STATIC_XML_SOURCE_AND_BYTECODE plus four executions of the pure UUID String helper; full runner not executed',
    provenance=provenance,historical_crosswalk_counts=dict(collections.Counter(r['cct_classification'] for r in rows)),
    comparison_complete=False,requirements=crosswalk,reviewed_differences=differences,
    limits=['53 data-model reference rows still require complete semantic comparison; overlap is not equivalence',
            'Only four UUID helper inputs were also executed against reference bytecode; no full reference card test was run',
            'B/C middleware and card-edge vectors are different scope, not missing Part1 assertions'])
probe=ROOT/'standards/nist-uuid-probe.tsv'
data['uuid_helper_probe']=dict(path=str(probe.relative_to(ROOT)),sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
    results=list(csv.DictReader(probe.open(),delimiter='\t')),generator='scripts/standards/NistUuidProbe.java',
    runtime='Java17 with original reference bytecode and BC1.66; only compareUuid(String,String) is invoked')
(ROOT/'standards/nist-comparison.json').write_text(json.dumps(data,indent=2)+'\n')
print(len(rows),'historical reference rows;',len(differences),'reviewed behavioral differences')
