# Working on CCT

## Read on start or resume

For modernization work, read [CCT_TEST_MODERNIZATION_PLAN.md](CCT_TEST_MODERNIZATION_PLAN.md) before editing, including its current position and next action. On resuming after context loss, reread that checkpoint. Read the relevant entries in [standards/reviewed-deltas.md](standards/reviewed-deltas.md) before changing a requirement. These are the active plan and detailed decisions; older proposals do not define current scope.

## Implementation discipline

- Modernize the existing SP 800-85B-derived CCT profile/database/atom/decoder path. Preserve the normal application workflow. Do not expand the parallel candidate validator or create a replacement execution system.
- Before adding code, search for and trace the existing assertion, helper, decoder, profile mapping and tests. Reuse or correct them. Justify each new file and remove obsolete duplication when its replacement is proved.
- Separate actual standards changes, existing bugs, missing tests and unchanged behavior. Record the exact final clause/table/footnote and applicability before changing an outcome. Historical 85B draft provenance is not a current final requirement.
- Require positive and intended-failure evidence through original CCT mappings for each delivered change. Helper tests and repeated invocation counts do not establish production coverage or a conformance percentage.
- Maintain profile source XLSX, generated SQL and shipped DB consistently. Preserve historical test IDs and add current citations. Version behavior only for demonstrated requirement differences and supported profile needs.
- Keep generated inventories in ignored build artifacts. Keep Java/build/package changes separate from standards changes; use the established Java 17 baseline unless the user changes scope.

## Leave a reliable checkpoint

At meaningful stopping points and before a commit or handoff, update the existing plan's status, evidence, decisions, unresolved issues and next action. Inspect the diff for unnecessary new files, duplicated validation and stale claims. Record tests actually run and their limits; verify published-head PR/security checks before claiming external readiness. Avoid additional overlapping plans or status files.
