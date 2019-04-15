package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import java.util.Arrays;

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
import gov.gsa.pivconformance.card.client.DiscoveryObject;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SP800_73_4DiscoveryObjectTests {
	

    private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4DiscoveryObjectTests.class);

	//Discovery Object blob no larger than 19 bytes
	@DisplayName("SP800-73-4.38 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
	void sp800_73_4_Test_38(String oid, TestReporter reporter) {
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
		assertTrue(bertlv.length <= 20);
		
		assertTrue(bertlv[bertlv.length-1] == 0x00);
	}

	//Discovery Object BERTLV tag is FE
	@DisplayName("SP800-73-4.39 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
	void sp800_73_4_Test_39(String oid, TestReporter reporter) {
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

		//Confirm that we were able to successfully retrieve and decode Discovery Object using tag 0xFE
		assertTrue(decoded = true);
	}
	
	//Discovery Object Tags 0x4F, 0x5F2F present in that order
	@DisplayName("SP800-73-4.40 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
    void sp800_73_4_Test_40(String oid, TestReporter reporter) {
        assertNotNull(oid);
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        assertNotNull(css);
        if(css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
        	ConformanceTestException e  = new ConformanceTestException("Login has already been attempted and failed. Not trying again.");
        	fail(e);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
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
		
		List<BerTag> tagList = ((DiscoveryObject) o).getTagList();
		
		BerTag cardAppAIDTag = new BerTag(TagConstants.PIV_CARD_APPLICATION_AID_TAG);
		BerTag pinUsagePolicyTag = new BerTag(TagConstants.PIN_USAGE_POLICY_TAG);
		
		//Confirm (0x4F, 0x5F2F) are present 
		assertTrue(tagList.contains(cardAppAIDTag));
		assertTrue(tagList.contains(pinUsagePolicyTag));
		
		int tagIndex = tagList.indexOf(cardAppAIDTag);
		
		//Confirm (0x4F, 0x5F2F) tag order
		assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.PIV_CARD_APPLICATION_AID_TAG));
		assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.PIN_USAGE_POLICY_TAG));

    }

	//Discovery Object no tags other than (0x4F, 0x5F2F) are present
	@DisplayName("SP800-73-4.41 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
	void sp800_73_4_Test_41(String oid, TestReporter reporter) {
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
		
		List<BerTag> tagList = ((DiscoveryObject) o).getTagList();
		
		BerTag cardAppAIDTag = new BerTag(TagConstants.PIV_CARD_APPLICATION_AID_TAG);
		BerTag pinUsagePolicyTag = new BerTag(TagConstants.PIN_USAGE_POLICY_TAG);
		
		//Confirm only two tags are present
		assertTrue(tagList.size() == 2);
		
		//Confirm (0x4F, 0x5F2F) are present 
		assertTrue(tagList.contains(cardAppAIDTag));
		assertTrue(tagList.contains(pinUsagePolicyTag));
			
	}
	
	//Discovery Object The PIN usage policy matches the card capabilities provided by the vendor documentation. 
	//Associated optional data objects are present when the PIN usage policy asserts an optional capability (i.e., OCC, global PIN and pairing code)
	@DisplayName("SP800-73-4.42 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
	void sp800_73_4_Test_42(String oid, TestReporter reporter) {
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
		
		boolean globalPINisPrimary = ((DiscoveryObject) o).globalPINisPrimary();
		
		if(globalPINisPrimary) {
			s_logger.info("Global PIN is the primary PIN used to satisfy the PIV ACRs for command execution and object access.");

			try {
				css.setGlobalPin("123456");
				CardUtils.authenticateInSingleton(true);
			} catch (ConformanceTestException e) {
				fail(e);
			}
		} else {
			s_logger.info("PIV Card Application PIN is the primary PIN used to satisfy the PIV ACRs for command execution and object access.");

			try {
				css.setApplicationPin("123456");
				CardUtils.authenticateInSingleton(false);
			} catch (ConformanceTestException e) {
				fail(e);
			}
		}
			
	}
	
	private static Stream<Arguments> sp800_73_4_DiscoveryObjectTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.DISCOVERY_OBJECT_OID));

	}

}
