package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;

public class X509DataObjectTests {
    @DisplayName("Test X.509 Data Object parsing")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("dataObjectTestProvider")
    void dataObjectTest(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			fail(e);
		}
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
    }

    
    private static Stream<Arguments> dataObjectTestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
