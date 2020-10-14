package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVMiddleware;
import gov.gsa.pivconformance.cardlib.card.client.PIVMiddlewareVersion;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PIVMiddlewareTests {
    @Test
    @DisplayName("PIV Middleware version status")
    void pivMiddlewareVersionStatusTest() {
        PIVMiddlewareVersion v = new PIVMiddlewareVersion();
        MiddlewareStatus status = PIVMiddleware.pivMiddlewareVersion(v);
        assertEquals(status, MiddlewareStatus.PIV_OK);
    }

    @Test
    @DisplayName("Check middleware version")
    void pivMiddlewareVersionTest(TestReporter reporter) {
        PIVMiddlewareVersion v = new PIVMiddlewareVersion();
        MiddlewareStatus status = PIVMiddleware.pivMiddlewareVersion(v);
        assertEquals(status, MiddlewareStatus.PIV_OK);
        assertEquals(v.getVersion(), "800-73-4 Client API");
        reporter.publishEntry("Version", v.getVersion());
    }


}
