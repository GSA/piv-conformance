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
