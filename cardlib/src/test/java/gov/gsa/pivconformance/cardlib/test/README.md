## Parser fixtures

The seven data-object parser test classes use the eight locally generated inputs
in `src/test/resources/gov/gsa/pivconformance/cardlib/test/synthetic/`; its README
describes their provenance and regeneration. No captured biometric data or
third-party card corpus is included. These are decode smoke tests; header-only
face/fingerprint records do not establish biometric conformance. Production-row
positive and intended-failure regressions live in Conformancelib's
`ExistingCctRegressionTest` and reuse the explicitly synthetic inputs.

## Hardware-test safety

Tests tagged `Hardware` may access a connected smart-card reader. Tests tagged
`PIN` are excluded from the general hardware lane and require both explicit
approval of a lab/test card and a PIN supplied through the process environment.
There is no default PIN.

From the `cardlib` directory, run the PIN lane without placing the PIN in the
Gradle command line:

```sh
read -s CCT_TEST_CARD_PIN
export CCT_TEST_CARD_PIN
CCT_APPROVED_TEST_CARD=true ./gradlew pinHardwareTest
unset CCT_TEST_CARD_PIN
```
