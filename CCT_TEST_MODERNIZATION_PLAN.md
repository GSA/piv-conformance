# CCT modernization: active plan and work log

Updated 2026-10-06. This supersedes the earlier local 2026-09-10 redesign proposal. The plan was previously excluded from version control; this reset makes the active checkpoint reviewable in Git. This is the single active plan. Detailed requirement decisions belong in [reviewed-deltas.md](standards/reviewed-deltas.md), not a second competing plan.

## Objective and standards baseline

Modernize the existing CCT's applicable PIV data-model checks with the smallest justified changes, trace each changed behavior to an exact final requirement, and demonstrate it through the actual CCT execution path. Keep the existing profile/workbook/database, JUnit atom, decoder and GUI/CLI design.

The original testing guidance is **NIST SP 800-85B, PIV Data Model Test Guidelines**. The repository [README](README.md) links the August 2014 draft **SP 800-85B-4**. [testdata/README.md](conformancelib/testdata/README.md) identifies the four profile workbooks as 85B requirements; [developer documentation](docs/README.md#junit-tests) describes execution of 85B cases through JUnit atoms. Production SQL contains 85B identifiers such as `8.1.0.1` and explicitly references SP 800-73-4. These establish intended lineage, not complete implemented conformance to that edition.

[NIST discontinued development of draft 85B-4 on March 17, 2023](https://csrc.nist.gov/pubs/sp/800/85/b/4/ipd). It is historical test provenance, not a current final normative target. Preserve original test identifiers and record changed requirements separately; do not invent an 85B-5 edition or relabel the historical draft as final.

| Layer | Repository-declared historical basis | Final target for applicable data-model behavior |
|---|---|---|
| Parent PIV standard | FIPS 201-2 | FIPS 201-3 (January 2022), with explicit applicability and supporting SP citations |
| Data model | SP 800-73-4 Part 1 | SP 800-73-5 Part 1 (July 2024) |
| Cryptography | SP 800-78-4 | SP 800-78-5 (July 2024), including purpose/date conditions where applicable |
| Biometrics | SP 800-76-2 | SP 800-76-2 (July 2013); unchanged edition does not prove complete implementation |
| Test guidance | Draft SP 800-85B-4 | Preserve and update CCT's derived tests against the final requirements above |

Editions checked against [NIST's PIV publication list](https://csrc.nist.gov/projects/piv/piv-standards-and-supporting-documentation) on 2026-10-06. Recheck before submission. SP 800-85A addresses interface/middleware testing and is not a substitute for the 85B data-model baseline. Card-edge, physical-card and middleware qualification are separate from software data-model coverage. Audit PIV-I applicability separately; do not impose PIV requirements on it without justification.

## Current position and evidence

Implementation snapshot: `30cc9171`; standards [PR #328](https://github.com/GSA/piv-conformance/pull/328), based on engineering [PR #329](https://github.com/GSA/piv-conformance/pull/329). Original inventory baseline: `90f754d785f7fe4ca9fb19e1c66102da0608447d`; reviewed engineering head: `9a307425`. These are evidence anchors, not instructions to overwrite the working tree. Java 17 / Gradle 8.14.5 / BC 1.66 remain the established build baseline.

| Work | Status and limit |
|---|---|
| Historical inventory | Four databases indexed, 489 rows each. Mapping and outline counts are available as generated artifacts; full semantic review against 85B and final requirements is unfinished. |
| Candidate triage | 18 groups reviewed: six contain revision changes, twelve concern unchanged requirements. This is a subset, not a complete standards inventory. |
| Existing CCT bug fixes | UUID equality and RSA SHA-256 NULL parameters repaired in original atoms (`b70a0a21`). 36 positive/intended-failure regressions per provider pass through original DB rows, argument binding, atoms and decoders. |
| Engineering security | CA-bundle TLS trust/hostname bypass removed (`9a307425`); three regressions passed and foundation CodeQL passed on that head. This is not a whole-codebase security clearance. |
| Package reduction | Generated inventories moved out of source (`d29034ef`). At audit head the standards diff still had 60 new / 6 modified files and 10,442 added lines; much is metadata, but parallel runtime validation also remains. |
| Six standards-change groups | **Not delivered through the corresponding original production checks.** Candidate DB/helpers remain experimental and require consolidation/removal. |
| Last confidence run | At `30cc9171`: 1,082 passing invocations across engineering, original-path, candidate and synthetic suites. Repeated inputs are not distinct requirements. Historical external certificate suite still has 24 missing-file failures; hardware/PIN qualification was not run. |
| External readiness | Not ready for a complete-modernization claim. Last checked standards head had no GitHub check runs; foundation results do not establish standards PR results. Recheck published heads before submission. |

The old CCT has functioning implementation and some proven defects. We have not established that it was broadly broken. Excess additions resulted from expanding a parallel validator and evidence package before proving necessary changes in the existing system. The previous confidence audit was a self-review, not independent approval. No defensible overall completion percentage or full-delivery estimate exists until the applicable requirement inventory is reviewed.

## Execution plan and completion gates

1. **Establish the real baseline before expanding implementation.** Reuse `scripts/standards/inventory.py` and inspect each original profile's workbook/SQL/DB mapping, atom, helper and decoder. Trace historical case/assertion IDs to the actual 85B edition and underlying clauses. Separate executable assertions, outline headings, disabled/not-applicable cases, placeholders and unknowns. Compare from final requirements back to code as well, so requirements missing from the old catalog are found. Start with CCC as a bounded example, then cover the remaining families and all four profile differences. Exit: an explicit applicable inventory with evidence or an unresolved marker for every entry; no inference from assertion counts.
2. **Finish the reviewed delta and package disposition.** For each applicable behavior record historical citation, final clause/table/footnote, profile/presence conditions, original case/method, observed behavior, required change and evidence gap. Classify standards changes, existing bugs, missing tests and unchanged behavior separately. Review existing findings on CMS, certificate profiles, biometrics, optional objects, retired OIDs and result handling; these remain investigation items until proved. Mark every candidate file keep, migrate, defer or remove with a short reason. Exit: a justified implementation backlog and a smaller first-PR scope distinct from full modernization.
3. **Correct the existing paths one requirement family at a time.** Start with the reviewed CCC change. Edit the original atom/decoder and profile source where required. Keep XLSX, generated SQL and shipped DB consistent using the existing conversion flow. Preserve stable case IDs and add exact current citations. Retain version selection only for demonstrated old/current differences and a supported profile need. Consolidate UUID logic into the repaired existing path and use the established TLV decoder; characterize differences before deleting duplicate helpers. Transfer useful candidate vectors, then remove their unused helpers/DB generator, tasks and metadata references. Defer the separate certificate-path/corpus-recovery package from the first submission; preserve useful work in Git history. Exit per change: normal CCT selection reaches the modified assertion and useful historical behavior remains covered.
4. **Demonstrate each delivered behavior.** Exercise the production profile mapping through TestCaseModel/TestStepModel, parameter provider, JUnit atom, AtomHelper and the actual decoder. Require a valid positive and a specific intended failure, plus relevant boundary, optionality and provider cases. A negative must fail for the intended assertion, not setup or unrelated parsing. For a bug, reproduce the old failure first; for a standards change, demonstrate the expected old/current difference. Run the normal application entry point and result reporting for the delivered profile. Simulated acquisition supports software evidence; separately record actual card/PIN testing or its absence. Exit: source-derived expected results and runnable evidence for every delivered change.
5. **Submit a compact, truthful increment; continue to full scoped coverage.** Keep a concise delta summary, focused existing-code edits, necessary regression fixtures and reproduction commands; generate bulky inventories as artifacts. Review new-file necessity and duplication, inspect the final diff, and verify security findings and all relevant PR checks on the published commit. A partial PR must enumerate delivered items and open gaps without claiming complete current-standard conformance. Full completion requires every applicable final requirement in the reviewed data-model scope to have a justified disposition and evidence; the six candidate groups alone cannot establish it.

A temporary copy of a production profile database is reasonable for isolated tests. A separate replacement catalog plus new validators is not the delivery architecture. No more candidate framework expansion or speculative runtime redesign.

## Persistent work log and next action

- **2026-10-06 decision:** Reset around SP 800-85B-derived CCT execution. Replace stale redesign guidance, retain demonstrated fixes, finish baseline/requirements review, then consolidate existing code. Keep this plan current rather than adding more status documents.
- **Completed this reset:** Verified repository 85B provenance and NIST publication status; installed root startup instructions; marked the old technical-hardening proposal historical. Documentation only; no runtime behavior or tests changed.
- **Next concrete action:** Trace the original CCC family end to end, including 85B assertion identifiers, workbook/SQL/DB consistency, existing TLV decoding and 73-4 versus final 73-5 Table 9. Add the compact findings to `standards/reviewed-deltas.md`; retain generated row details under `build/standards/`. Use this first family to validate the review format before applying it to the rest.
- **Still open:** Complete baseline/applicability review; candidate file disposition and duplicate removal; six original-path integrations; broader missing requirements; normal-entry-point evidence; historical certificate fixtures; hardware qualification; final published-head checks.
- **At each meaningful checkpoint:** Update current position, evidence commit/commands/results, decisions and the next concrete action here. Record unresolved interpretations explicitly. Do not promote planned work or helper-only evidence to delivered status.
