package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import java.util.Arrays;
import java.util.Date;
import java.util.Calendar;

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
import gov.gsa.pivconformance.card.client.CardholderBiometricData;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_73_4FingerprintsTests {

	//Fingerprints container blob no larger than 4006 bytes
	@DisplayName("SP800-73-4.24 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_73_4_FingerprintsTestProvider")
	void sp800_73_4_Test_24(String oid, TestReporter reporter) {
		assertNotNull(oid);
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		assertNotNull(css);
		if (css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
			ConformanceTestException e = new ConformanceTestException(
					"Login has already been attempted and failed. Not trying again.");
			fail(e);
		}
		try {
			CardUtils.setUpPivAppHandleInSingleton();
			CardUtils.authenticateInSingleton(false);
		} catch (ConformanceTestException e) {
			fail(e);
		}

		// Get card handle and PIV handle
		CardHandle ch = css.getCardHandle();
		AbstractPIVApplication piv = css.getPivHandle();

		// Created an object corresponding to the OID value
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
		assertNotNull(o);

		// Get data from the card corresponding to the OID value
		MiddlewareStatus result = piv.pivGetData(ch, oid, o);
		assertTrue(result == MiddlewareStatus.PIV_OK);

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		//Check blob length
		assertTrue(bertlv.length <= 4006);
	}

	//Tags 0xBC and 0xFE are present in that order
	@DisplayName("SP800-73-4.25 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_73_4_FingerprintsTestProvider")
    void sp800_73_4_Test_25(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
			CardUtils.authenticateInSingleton(false);
		} catch (ConformanceTestException e) {
			fail(e);
		}
        
        //Get card handle and PIV handle
        CardHandle ch = css.getCardHandle();
        AbstractPIVApplication piv = css.getPivHandle();
        
        //Created an object corresponding to the OID value
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
    	
        //Get data from the card corresponding to the OID value
        MiddlewareStatus result = piv.pivGetData(ch, oid, o);
        assertTrue(result == MiddlewareStatus.PIV_OK);
        	
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		List<BerTag> tagList = ((CardholderBiometricData) o).getTagList();
		
		BerTag berFingerprintTag = new BerTag(TagConstants.FINGERPRINT_I_AND_II_TAG);
		BerTag berECTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		//Confirm (0xBC, 0xFE) are present 
		assertTrue(tagList.contains(berFingerprintTag));
		assertTrue(tagList.contains(berECTag));
		
		int tagIndex = tagList.indexOf(berFingerprintTag);
		
		//Confirm (0xBC, 0xFE) tag order
		assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.FINGERPRINT_I_AND_II_TAG));
		assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));

    }

	//No tags other than (0xBC, 0xFE) are present
	@DisplayName("SP800-73-4.26 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_73_4_FingerprintsTestProvider")
	void sp800_73_4_Test_26(String oid, TestReporter reporter) {
		assertNotNull(oid);
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		assertNotNull(css);
		if (css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
			ConformanceTestException e = new ConformanceTestException(
					"Login has already been attempted and failed. Not trying again.");
			fail(e);
		}
		try {
			CardUtils.setUpPivAppHandleInSingleton();
			CardUtils.authenticateInSingleton(false);
		} catch (ConformanceTestException e) {
			fail(e);
		}

		// Get card handle and PIV handle
		CardHandle ch = css.getCardHandle();
		AbstractPIVApplication piv = css.getPivHandle();

		// Created an object corresponding to the OID value
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
		assertNotNull(o);

		// Get data from the card corresponding to the OID value
		MiddlewareStatus result = piv.pivGetData(ch, oid, o);
		assertTrue(result == MiddlewareStatus.PIV_OK);


		boolean decoded = o.decode();
		assertTrue(decoded);
		
		List<BerTag> tagList = ((CardholderBiometricData) o).getTagList();
		
		BerTag berFingerprintTag = new BerTag(TagConstants.FINGERPRINT_I_AND_II_TAG);
		BerTag berECTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		//Confirm only two tags are present
		assertTrue(tagList.size() == 2);
		
		//Confirm (0xBC, 0xFE) are present 
		assertTrue(tagList.contains(berFingerprintTag));
		assertTrue(tagList.contains(berECTag));
			
	}
	
	private static Stream<Arguments> sp800_73_4_FingerprintsTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}

}
