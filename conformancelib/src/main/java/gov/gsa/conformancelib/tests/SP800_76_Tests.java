package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import java.nio.ByteBuffer;
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
import gov.gsa.pivconformance.card.client.CardCapabilityContainer;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.CardholderBiometricData;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_76_Tests {

	//BDB length field is non-zero
	@DisplayName("SP800-76.1 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_1(String oid, TestReporter reporter) {
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		 if (biometricData != null && biometricData.length > 8) {

             //Get Biometric data block (BDB) Length
             byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 2, 6);
             

     		assertNotNull(biometricDataBlockLengthBytes);
     		
     		//Convert Biometric data block (BDB) Length byte[] value to int
            ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
            int biometricDataBlockLength = wrapped.getInt();
            
            assertTrue(biometricDataBlockLength > 0);
		 }
	}

	
	//BDB length field is non-zero
	@DisplayName("SP800-76.2 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_2(String oid, TestReporter reporter) {
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		 if (biometricData != null && biometricData.length > 8) {

             //Get Biometric data block (BDB) Length
             byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 2, 6);
             

     		assertNotNull(biometricDataBlockLengthBytes);
     		
     		//Convert Biometric data block (BDB) Length byte[] value to int
            ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
            int biometricDataBlockLength = wrapped.getInt();
            
            assertTrue(biometricDataBlockLength > 0);
            
            //XXX Will need to revisit to confirm if this is the right way to test this
            assertTrue(biometricData.length >= (88 + 88 + biometricDataBlockLength));
            
		 }
	}
	
	//SB length field is non-zero
	@DisplayName("SP800-76.3 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_3(String oid, TestReporter reporter) {
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		 if (biometricData != null && biometricData.length > 6+8) {
			 
             //Get Signature block (SB) Length
             byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);
             

     		assertNotNull(signatureDataBlockLengthBytes);
     		
     		 //Convert Signature block (SB) Length byte[] value to int
     		ByteBuffer wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
            int signatureDataBlockLength = (int) wrapped.getShort();
            
            assertTrue(signatureDataBlockLength > 0);
		 }
	}
	
	//Card Holder Fingerprint object length equals sum of CBEFF header length + BDB length + SB length

	@DisplayName("SP800-76.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_4(String oid, TestReporter reporter) {
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		 if (biometricData != null && biometricData.length > 6+8) {
			 
			//Get Biometric data block (BDB) Length
			byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 2, 6);
			
			assertNotNull(biometricDataBlockLengthBytes);
			
			//Convert Biometric data block (BDB) Length byte[] value to int
			ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
			int biometricDataBlockLength = wrapped.getInt();
			           
			//Get Signature block (SB) Length
			byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);	
			assertNotNull(signatureDataBlockLengthBytes);
			
			//Convert Signature block (SB) Length byte[] value to int
			wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
			int signatureDataBlockLength = (int) wrapped.getShort();
			
			assertTrue(biometricData.length == (88 + biometricDataBlockLength + signatureDataBlockLength));

		 }
	}
	
	private static Stream<Arguments> sp800_76_BiometricTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID),
						Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}
	
	private static Stream<Arguments> sp800_76_FacialImageTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID));

	}
	
	private static Stream<Arguments> sp800_76_FingerprintsTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}

}
