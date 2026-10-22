package gov.gsa.pivconformance.cardlib.test;

import org.junit.jupiter.api.TestInfo;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

final class HardwareTestCredentials {
    private static final String APPROVED_CARD_ENVIRONMENT = "CCT_APPROVED_TEST_CARD";
    private static final String PIN_ENVIRONMENT = "CCT_TEST_CARD_PIN";

    private HardwareTestCredentials() {
    }

    static String pinFor(TestInfo testInfo) {
        if (!testInfo.getTags().contains("PIN")) {
            return null;
        }
        assumeTrue("true".equalsIgnoreCase(System.getenv(APPROVED_CARD_ENVIRONMENT)),
                "PIN interaction requires explicit approval of a lab/test card");
        String pin = System.getenv(PIN_ENVIRONMENT);
        assumeTrue(pin != null && !pin.isBlank(),
                "PIN interaction requires an externally supplied test-card PIN");
        return pin;
    }

    static String requirePinForApprovedTestCard() {
        assumeTrue("true".equalsIgnoreCase(System.getenv(APPROVED_CARD_ENVIRONMENT)),
                "PIN interaction requires explicit approval of a lab/test card");
        String pin = System.getenv(PIN_ENVIRONMENT);
        assumeTrue(pin != null && !pin.isBlank(),
                "PIN interaction requires an externally supplied test-card PIN");
        return pin;
    }
}
