package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import java.util.Arrays;


import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Disabled;
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
import gov.gsa.pivconformance.card.client.CardCapabilityContainer;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_73_4CCCTests {

	//CCC blob no larger than 297 bytes
	@DisplayName("SP800-73-4.1 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_70_3_CCCTestProvider")
	void sp800_73_4_Test_1(String oid, TestReporter reporter) {
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

		assertTrue(bertlv.length <= 297);
	}

	//CCC BERTLV tag is '5FC107'
	@DisplayName("SP800-73-4.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_70_3_CCCTestProvider")
    void sp800_73_4_Test_2(String oid, TestReporter reporter) {
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
        	
        byte[] bertlv = o.getBytes();
        
        //pivGetData retrives data based on the tag value for CCC its '5FC107'
        assertNotNull(bertlv);
    }

	//CCC Tags 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xFA, 0xFB, 0xFC, 0xFD present in that order
	@DisplayName("SP800-73-4.3 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_70_3_CCCTestProvider")
	void sp800_73_4_Test_3(String oid, TestReporter reporter) {
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
		
		List<BerTag> tagList = ((CardCapabilityContainer) o).getTagList();
		
		assertTrue(tagList.size() >= 12);
		
		assertTrue(Arrays.equals(tagList.get(0).bytes,TagConstants.CARD_IDENTIFIER_TAG));
		assertTrue(Arrays.equals(tagList.get(1).bytes,TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG));
		assertTrue(Arrays.equals(tagList.get(2).bytes,TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG));
		assertTrue(Arrays.equals(tagList.get(3).bytes,TagConstants.APPLICATIONS_CARDURL_TAG));
		assertTrue(Arrays.equals(tagList.get(4).bytes,TagConstants.PKCS15_TAG));
		assertTrue(Arrays.equals(tagList.get(5).bytes,TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG));
		assertTrue(Arrays.equals(tagList.get(6).bytes,TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG));
		assertTrue(Arrays.equals(tagList.get(7).bytes,TagConstants.CARD_APDUS_TAG));
		assertTrue(Arrays.equals(tagList.get(8).bytes,TagConstants.REDIRECTION_TAG_TAG));
		assertTrue(Arrays.equals(tagList.get(9).bytes,TagConstants.CAPABILITY_TUPLES_TAG));
		assertTrue(Arrays.equals(tagList.get(10).bytes,TagConstants.STATUS_TUPLES_TAG));
		assertTrue(Arrays.equals(tagList.get(11).bytes,TagConstants.NEXT_CCC_TAG));
		
		 
		

	    //public static final byte[] EXTENDED_APPLICATION_CARDURL_TAG = { (byte) 0xE3 };
	    //public static final byte[] SECURITY_OBJECT_BUFFER_TAG = { (byte) 0xB4 };
		
	}
	
	//CCC Optional Tags 0xE3 and 0xE4 may be present or absent; if present are after tags listed in 73-4.3and are in that order
	@DisplayName("SP800-73-4.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_70_3_CCCTestProvider")
	void sp800_73_4_Test_4(String oid, TestReporter reporter) {
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
		
		List<BerTag> tagList = ((CardCapabilityContainer) o).getTagList();	
		
		BerTag berextendedAppCarlUrlTag = new BerTag(TagConstants.EXTENDED_APPLICATION_CARDURL_TAG);
		BerTag berSecurityObjectBufferTag = new BerTag(TagConstants.SECURITY_OBJECT_BUFFER_TAG);
		if(tagList.contains(berextendedAppCarlUrlTag))
		{
		
			assertTrue(tagList.size() >= 13);
			assertTrue(Arrays.equals(tagList.get(0).bytes,TagConstants.CARD_IDENTIFIER_TAG));
			assertTrue(Arrays.equals(tagList.get(1).bytes,TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG));
			assertTrue(Arrays.equals(tagList.get(2).bytes,TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG));
			assertTrue(Arrays.equals(tagList.get(3).bytes,TagConstants.APPLICATIONS_CARDURL_TAG));
			assertTrue(Arrays.equals(tagList.get(4).bytes,TagConstants.PKCS15_TAG));
			assertTrue(Arrays.equals(tagList.get(5).bytes,TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG));
			assertTrue(Arrays.equals(tagList.get(6).bytes,TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG));
			assertTrue(Arrays.equals(tagList.get(7).bytes,TagConstants.CARD_APDUS_TAG));
			assertTrue(Arrays.equals(tagList.get(8).bytes,TagConstants.REDIRECTION_TAG_TAG));
			assertTrue(Arrays.equals(tagList.get(9).bytes,TagConstants.CAPABILITY_TUPLES_TAG));
			assertTrue(Arrays.equals(tagList.get(10).bytes,TagConstants.STATUS_TUPLES_TAG));
			assertTrue(Arrays.equals(tagList.get(11).bytes,TagConstants.NEXT_CCC_TAG));
			assertTrue(Arrays.equals(tagList.get(12).bytes,TagConstants.EXTENDED_APPLICATION_CARDURL_TAG));
		}
		
		if(tagList.contains(berSecurityObjectBufferTag))
		{
			assertTrue(tagList.size() >= 14);
			assertTrue(Arrays.equals(tagList.get(0).bytes,TagConstants.CARD_IDENTIFIER_TAG));
			assertTrue(Arrays.equals(tagList.get(1).bytes,TagConstants.CAPABILITY_CONTAINER_VERSION_NUMBER_TAG));
			assertTrue(Arrays.equals(tagList.get(2).bytes,TagConstants.CAPABILITY_GRAMMAR_VERSION_NUMBER_TAG));
			assertTrue(Arrays.equals(tagList.get(3).bytes,TagConstants.APPLICATIONS_CARDURL_TAG));
			assertTrue(Arrays.equals(tagList.get(4).bytes,TagConstants.PKCS15_TAG));
			assertTrue(Arrays.equals(tagList.get(5).bytes,TagConstants.REGISTERED_DATA_MODEL_NUMBER_TAG));
			assertTrue(Arrays.equals(tagList.get(6).bytes,TagConstants.ACCESS_CONTROL_RULE_TABLE_TAG));
			assertTrue(Arrays.equals(tagList.get(7).bytes,TagConstants.CARD_APDUS_TAG));
			assertTrue(Arrays.equals(tagList.get(8).bytes,TagConstants.REDIRECTION_TAG_TAG));
			assertTrue(Arrays.equals(tagList.get(9).bytes,TagConstants.CAPABILITY_TUPLES_TAG));
			assertTrue(Arrays.equals(tagList.get(10).bytes,TagConstants.STATUS_TUPLES_TAG));
			assertTrue(Arrays.equals(tagList.get(11).bytes,TagConstants.NEXT_CCC_TAG));
			assertTrue(Arrays.equals(tagList.get(12).bytes,TagConstants.EXTENDED_APPLICATION_CARDURL_TAG));
			assertTrue(Arrays.equals(tagList.get(13).bytes,TagConstants.SECURITY_OBJECT_BUFFER_TAG));
		}
	}
	
	//CCC Tag 0xFE present and after any tags from 73-4.3 and 73-4.4
	@DisplayName("SP800-73-4.5 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_70_3_CCCTestProvider")
	void sp800_73_4_Test_5(String oid, TestReporter reporter) {
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
		
		List<BerTag> tagList = ((CardCapabilityContainer) o).getTagList();
		
		boolean edc = ((CardCapabilityContainer) o).getErrorDetectionCode();

		assertTrue(edc);
		
		int length = tagList.size();
		
		//Confirm that error detection code tag is last
		assertTrue(Arrays.equals(tagList.get(length-1).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));

	}
	
	//Values of tags present conform to vendor-supplied data
	@DisplayName("SP800-73-4.6 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_70_3_CCCTestProvider")
	@Disabled //DIsabled for now because we really don't know how to test that now.
	void sp800_73_4_Test_6(String oid, TestReporter reporter) {
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
		
		//XXX Not sure what vendor supplied data is to check values of tags	
	}
	
	//No tags other than (0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xFA, 0xFB, 0xFC, 0xFD, 0xE3, 0xE4, 0xFE) are present
	@DisplayName("SP800-73-4.7 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_70_3_CCCTestProvider")
	void sp800_73_4_Test_7(String oid, TestReporter reporter) {
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
		
		List<BerTag> tagList = ((CardCapabilityContainer) o).getTagList();
		
		List<byte[]> allCCCTags = TagConstants.AllCCCTags();
		for(BerTag tag : tagList) {

			//Check that the tag is present in the all CCC tags list
			boolean present = false;
			for (int i = 0; i < allCCCTags.size(); i++) {
				
				if(Arrays.equals(allCCCTags.get(i), tag.bytes)) {
					present = true;
					break;
				}
			}
			assertTrue(present);
		}
	}
	
	private static Stream<Arguments> sp800_70_3_CCCTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_CAPABILITY_CONTAINER_OID));

	}

}
