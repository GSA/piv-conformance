## Parser fixtures

The seven data-object parser test classes use only the Golden PIV and Golden
PIV-I objects from the GSA ICAM test-card corpus. The retained files and hashes
are listed in `src/test/resources/gov/gsa/pivconformance/cardlib/test/gsa-icam-card-builder/MANIFEST.sha256`.
These are decode smoke tests; scenario names such as "tampered" or "expired" do
not establish a CCT conformance verdict. Production-row positive and intended
failure regressions live in Conformancelib's `ExistingCctRegressionTest`.

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
