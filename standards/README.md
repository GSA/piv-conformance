# Current standards candidate — technical review snapshot

**NOT YET READY.** This profile provides selected PIV data-model assertions and reproducible evidence. It does not provide a complete current-standard card verdict. The complete atomic requirement denominator, semantic historical audit, CMS/integrity checks, certificate profiles, biometric payload checks and conditional applicability remain unfinished. See [readiness.json](readiness.json) for specific technical gaps.

This directory is maintained product traceability. Counts below describe this snapshot, not percentages of NIST conformance. Final publications control behavior; reference-runner behavior and SP 800-85B methodology do not override them. Draft SP 800-85B-4 was discontinued and is historical provenance only. No draft SP 800-73-6 or SP 800-78-6 requirement is used as a gate.

## Baseline and scope

The protected starting commit is `90f754d785f7fe4ca9fb19e1c66102da0608447d`, initially on `modernization/01-hermetic-test-baseline`. The local safety ref is `safety/pre-nist-2026-09-30`; standards work is on `feature/nist-current-standards-candidate`. The frozen engineering baseline tag is `cct-modernization-baseline-2026-09-11`. [baseline.json](baseline.json) records versions, hashes, the four commits above that tag, original test results and the separate packaging commit.

Java 17, Gradle 8.14.5, BC 1.66 and build.version 1.0.7 are preserved. All four production databases, the historical parser-fixture manifest and protected packaging files are unchanged. Standards commits remain separate from Windows packaging. Nothing has been pushed.

The primary target is the PIV data model in SP 800-73-5 Part 1. Selected SP 800-78-5 active-key assertions use the **through-2030** column. They do not apply active-key restrictions to archived/retired signatures. SP 800-76-2 supplies selected fingerprint CBEFF fields. FIPS 201-3 cross-cutting applicability is not yet fully mapped. PIV-I databases retain historical behavior; no current PIV-I verdict is offered.

Part 2 APDU, activation/access-control and physical behavior are identified as hardware scope. Part 3 middleware qualification is out of scope. Reading card bytes in a data-model atom is an acquisition dependency, not evidence of card-edge qualification.

The normative source PDFs, URLs and hashes are in [sources.json](sources.json):

- [SP 800-73-5 Part 1, final July 2024](https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final).
- [SP 800-78-5, final July 2024](https://csrc.nist.gov/pubs/sp/800/78/5/final).
- [SP 800-76-2, final July 2013](https://csrc.nist.gov/pubs/sp/800/76/2/final).
- [FIPS 201-3, final January 2022](https://csrc.nist.gov/pubs/fips/201-3/final).

Incorporated PKIX/crypto assertions identify RFC 5280, RFC 3279, RFC 4055, RFC 5758 and RFC 4122 at the relevant manifest rule. The candidate does not claim blanket PKIX/CMS compliance.

## Historical inventory and delta

[historical-cases.json](historical-cases.json), [historical-steps.json](historical-steps.json) and [historical-methods.json](historical-methods.json) preserve the baseline database-to-code paths, source bodies and actual assertion calls. Unknown semantic bindings remain explicit. [historical-findings.json](historical-findings.json) records reviewed defects; [historical-summary.json](historical-summary.json) records totals.

| Database | Rows | Executable rows | Outline rows | Enabled rows | Referenced methods |
|---|---:|---:|---:|---:|---:|
| PIV Production | 489 | 382 | 107 | 489 | 140 |
| PIV ICAM | 489 | 382 | 107 | 489 | 140 |
| PIV-I Production | 489 | 371 | 118 | 489 | 135 |
| PIV-I ICAM | 489 | 371 | 118 | 274 | 135 |

There are 187 indexed source methods, including 140 unique database-referenced methods. All referenced methods resolve. Source dispositions are 176 partial, five description/code mismatches, five placeholders and one unconditional pass. Source-only quality is Q0=6 and Q1=181; it is not fixture-proven standards coverage.

Known problems include a UUID helper that ignores its expected identifier, an unconditional placeholder, BER/APDU proxy assertions, optional early returns, conditional biometric assertion guards, EKU presence without criticality, contradictory RSA size checks, provider-string curve matching and an inverted RSA NULL-parameter assertion. Full assertion-dominance and semantic review remains incomplete.

The candidate manifest contains nine CHANGED groups, eight UNCHANGED groups with new evidence, one CONDITIONAL group and ten aggregate gap/scope records awaiting atomic classification. These are not counts of every normative delta. Removed fields are represented within changed groups, rather than counted again as separate coverage. New Java code for an existing requirement is not labeled a NEW normative requirement.

## Implemented assertions and traceability

[current-manifest.json](current-manifest.json) maps source sections/tables to candidate methods, historical associations, fixture IDs, expected outcomes, quality and limitations. Historical associations may be family-level; they are not assertions of behavioral equivalence.

The candidate adds:

- CCC field order/length/data-model rules and rejection of removed E3/B4 fields.
- CHUID field structure, removed fields, calendar date, permitted card UUID variants/versions and optional version-4 cardholder UUID.
- Active certificate TLV/CertInfo rules without treating the 1856-byte recommendation as a hard maximum. Retired certificates separately retain the optional MSCUID exception in Tables 21–40.
- Security Object mapping triples and Table 13 value maxima, BA≤30 and BB≤1298. CMS/hash integrity remains missing.
- Key History unsigned counts, 20-slot limit, conditional URL presence, DNS/hash representation and URL length.
- Printed Information field/ASCII/date limits and eight-decimal-digit Pairing Code representation when present.
- Active RSA2048/RSA3072, exponent65537, named P-256/P-384 and actual EC-point validity; DER/SPKI parameter checks.
- RSA SHA256/SHA384, ECDSA SHA256/SHA384 and PSS AlgorithmIdentifier checks, with malformed parameters rejected. Issuer keys, key-use relationships and cryptographic signature verification remain separate gaps.
- CHUID-to-certificate card UUID equality, and selected mandatory fingerprint CBEFF header fields, unsigned lengths, binary dates, creator/quality fields, FASC-N link and reserved bytes.

Historical atoms and databases were preserved rather than relabeled as current. A fresh database is generated at `conformancelib/build/standards/CURRENT_2026_CANDIDATE.db`, using the historical schema with **35 candidate rows**, explicit PARTIAL SCOPE descriptions and `NOT_YET_READY` metadata. Repeated containers do not create new requirements. No dual-profile UI redesign was introduced.

**The generated database is an execution/review artifact, not a complete card-verdict product.** Absent conditional objects abort in JUnit because applicability is unknown. The Swing listener now reports these candidate aborts as SKIP while preserving historical abort behavior. Legacy retired-key OID aliases still require reconciliation with the normative OIDs and wire-tag mapping.

## Evidence and measurement

[metrics.json](metrics.json) is generated by `scripts/standards/verify.py` from actual JUnit reports, fixture hashes and mappings. Negative vectors count only when the expected assertion's rule ID caused the failure. Unrelated setup or parser failures do not earn negative evidence.

| Final publication | Groups with assertions | Aggregate gaps/scope records | Atomic applicable denominator |
|---|---:|---:|---|
| SP 800-73-5 Part 1 | 13 | 4 | Unresolved |
| SP 800-78-5 | 4 | 2 | Unresolved |
| SP 800-76-2 | 1 | 1 | Unresolved |
| FIPS 201-3 | 0 | 2 | Unresolved |

One additional record marks Part 3 out of scope. The **28 group/gap records are not a denominator**. Their quality distribution is Q0=10, Q1=0, Q2=1, Q3=17, Q4=0, Q5=0. Boundary and malformed evidence exists, but comprehensive atomic coverage and independent validation are not established. [source-locators.json](source-locators.json) contains 1318 modal-text locators for audit; those are not deduplicated requirements.

There are **264 distinct deterministic synthetic inputs**: 167 data-model, 53 crypto and 44 linkage/header vectors. Expected outcomes are 63 passes and 201 intended failures. Input-kind counts are 29 positive, 86 negative, 87 boundary, 52 malformed and 10 conditional; these labels and outcome counts are different dimensions. No real cardholder or biometric data is used. Structural fixture payloads are deliberately placeholders and do not prove entire credentials valid.

| Lane | Result | Meaning |
|---|---:|---|
| Engineering: Cardlib | 446 passed | Preserved engineering regression |
| Engineering: Conformancelib | 8 passed | Preserved engineering regression |
| Engineering: Swing/#326 | 12 passed | Eight protected tests plus four candidate result-status regressions |
| Current candidate | 466 passed | 264 direct inputs + 167 repeated through DB/JUnit/acquisition + 35 absence checks |
| Synthetic certificate evidence | 75 passed | Separate SUN/BC path/policy and malformed/boundary evidence |
| Historical external certificates | 24 missing-file failures | Preserved unresolved original corpus lane |
| Historical card-profile conformance | Not run | Not inferred from engineering tests |
| Physical hardware/PIN | Not run | Separate qualification |

The protected engineering total is **462/462**, with four additional Swing status tests, separate from standards evidence. The 35 absence checks prove 12 required-object failures and 23 conditional-object aborts; these are successful evidence tests, not 35 card PASS verdicts.

## Certificate recovery and reference comparison

[certificate-corpus.json](certificate-corpus.json) records the 12 missing filenames, intended policy OIDs, per-file synthetic mappings and provenance limits. The search covered available local history/tags/artifacts, adjacent repository filenames, policy/configuration references and **all 21 assets across 35 published GSA releases**. Release archives contained 120 matching entries, all encrypted. No originals were decrypted or used; authoritative semantic recovery remains unresolved.

The 17-file synthetic public corpus is generated with a documented public seed under Java17/BC1.66; no private keys are written. Regeneration matches every committed byte. SUN and BC validate at fixed `2026-09-30T12:00:00Z`. Tests cover 12 policy-positive paths per provider, wrong/missing policies, validity boundaries, expiration, bad signatures, malformed DER and fixture hashes. Equivalence is limited to generic path/policy intention; original federal chains, policies, AIA and revocation are not reproduced. Synthetic fixtures have no network locations; the generic builder API is not a network sandbox for arbitrary future inputs.

[nist-comparison.json](nist-comparison.json) records NIST PIV Test Runner 5.0.1 (20200212-0308), source/bytecode hashes and 140 historical reference rows. Of these, 87 are different scope. The prior historical crosswalk identifies 37 overlaps (including two with placeholders), seven placeholder-only and nine unimplemented data-model entries; these are not current behavioral equivalence counts.

Six reviewed differences cover RSA3072, RSA SHA384, PSS SHA384, historical SHA1 cutoff, the old CCT UUID comparison defect and UUID encoding strictness. Four synthetic inputs were executed against the original runner's pure UUID comparison helper: it accepts no-hyphen and bare UUID forms that the candidate rejects. The full NIST runner was not executed. Complete comparison of the 53 data-model rows remains unfinished. No reference implementation source was copied into candidate assertions.

## Interpretation questions

[decisions.json](decisions.json) contains precise source bindings, alternatives and impacts:

1. How should the 2031 algorithm columns be reconciled with SHOULD/agency-deferral language, and which issuance, expiry, usage or evaluation date governs?
2. Which exact final PIV-I policy/profile and exceptions should a current PIV-I candidate evaluate?
3. Does Table 19's fixed 12-byte Discovery AID contain an error, given section 3.3.2's `4F 0B` eleven-byte example; which lengths should pass?

The earlier Security Object size question is resolved: Table 13 gives maxima without the exceptions attached to certificate entries. BA/BB over-limit values now fail; hypothetical interoperability concerns do not authorize relaxing final text.

## Reproduction

Set `JAVA_HOME` to a Java17 JDK, with Python3 available. The observed runtime was Temurin17.0.20.1+1. These commands use the existing module builds and ignored `build/`/`libs/` outputs; they do not run hardware tests or package Windows distributions. Omit `--offline` only when intentionally populating a new dependency cache.

```sh
python3 scripts/standards/inventory.py
python3 scripts/standards/generate_vectors.py
python3 scripts/standards/generate_crypto_vectors.py
python3 scripts/standards/generate_linked_vectors.py
python3 scripts/standards/refresh_manifest.py
(cd cardlib && ./gradlew install --offline)
(cd conformancelib && ./gradlew install currentCandidateTest certificateFixtureTest --offline)
(cd tools/85b-swing-gui && ./gradlew test --offline)
JAVA_HOME="$JAVA_HOME" python3 scripts/standards/generate_certificates.py
# Expected nonzero until the original external corpus is resolved:
(cd conformancelib && ./gradlew historicalCertificateFixtureTest --offline)
JAVA_HOME="$JAVA_HOME" python3 scripts/standards/verify.py
git diff --check
```

`currentCandidateTest` automatically regenerates the candidate DB. Verification checks preserved hashes, fixture bytes, rule-specific failure links and lane counts. It requires the historical lane's failures to be the documented missing-file failures. The local NIST comparison additionally requires the separately held reference analysis tree; `nist_comparison.py` and `NistUuidProbe.java` document that path-independent workflow. Release-search metadata and asset hashes are preserved; downloaded archives are not committed.
