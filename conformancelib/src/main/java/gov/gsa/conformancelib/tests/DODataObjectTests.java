package gov.gsa.conformancelib.tests;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

public class DODataObjectTests {
    @DisplayName("Read discovery object from card")
    void dataObjectTest(TestReporter reporter) {
    	CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        }
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.DISCOVERY_OBJECT_OID);
        assertNotNull(o);
        reporter.publishEntry(APDUConstants.DISCOVERY_OBJECT_OID, o.getClass().getSimpleName());
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, APDUConstants.DISCOVERY_OBJECT_OID, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
        assertNotNull(((DiscoveryObject) o).getSignedContent());
    }
}
