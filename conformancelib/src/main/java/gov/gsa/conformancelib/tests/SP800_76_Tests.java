package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;
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

	
	//Recorded length matches actual length
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		 if (biometricData != null && biometricData.length > 8) {
			 
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
			           
			//Get Signature block (SB) Length
			byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);	
			assertNotNull(signatureDataBlockLengthBytes);
			
			//Convert Signature block (SB) Length byte[] value to int
			wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
			int signatureDataBlockLength = (int) wrapped.getShort();
			
			assertTrue(biometricData.length == (88 + biometricDataBlockLength + signatureDataBlockLength));

		 }
	}
	
	//Patron Header Version is 0x03
	@DisplayName("SP800-76.5 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_5(String oid, TestReporter reporter) {
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		assertTrue(biometricData.length > 1);
		
		//Check the first byte of biometric data to confirm its is 0x03
		assertTrue(Byte.compare(biometricData[0], (byte)0x03) == 0);
	}
	
	//SBH security options field has value b00001101 (0x0D)
	@DisplayName("SP800-76.6 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_6(String oid, TestReporter reporter) {
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		assertTrue(biometricData.length > 2);
		
		//Check the second byte of biometric data to confirm its is b00001101 (0x0D)
		assertTrue(Byte.compare(biometricData[1], (byte)0x0D) == 0);
	}
	
	//BDB Format Owner field has a value of 0x001B
	@DisplayName("SP800-76.7 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_7(String oid, TestReporter reporter) {
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
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		assertTrue(biometricData.length >= 10);
		
		//Check the 8th and 9th bytes of biometric data to confirm BDB Format Owner field has a value of 0x001B
		assertTrue(Byte.compare(biometricData[8], (byte)0x00) == 0);
		assertTrue(Byte.compare(biometricData[9], (byte)0x1B) == 0);
	}
	
	//Card Holder Facial Image object length equals sum of CBEFF header length + BDB length + SB length
	@DisplayName("SP800-76.8 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_8(String oid, TestReporter reporter) {
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
			           
			//Get Signature block (SB) Length
			byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);	
			assertNotNull(signatureDataBlockLengthBytes);
			
			//Convert Signature block (SB) Length byte[] value to int
			wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
			int signatureDataBlockLength = (int) wrapped.getShort();
			
			
			//Confirm Card Holder Facial Image object length equals sum of CBEFF header length + BDB length + SB length
			assertTrue(biometricData.length == (88 + biometricDataBlockLength + signatureDataBlockLength));

		 }
	}
	
	//Extract contents of format identifier, confirm value 0x464D5200
	@DisplayName("SP800-76.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_9(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
		
		assertTrue(biometricDataBlock.length >= 4);
		
		//Get first 4 bytes of biometric data block to get format identifier.
		byte [] formatIdentifier = Arrays.copyOfRange(biometricDataBlock, 0, 4);
		byte [] formatIdentifierValueToCheck = { 0x46, 0x4D, 0x52, 0x00 };
		
		//Check  format identifier value of 0x464D5200
		assertTrue(Arrays.equals(formatIdentifier, formatIdentifierValueToCheck));
	}
	
	//Extract contents of version identifier, confirm value 0x20323030
	@DisplayName("SP800-76.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_10(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
		
		assertTrue(biometricDataBlock.length >= 8);
		
		//Get bytes 4 through 8 of biometric data block to get version identifier.
		byte [] versionIdentifier = Arrays.copyOfRange(biometricDataBlock, 4, 8);
		byte [] versionIdentifierValueToCheck = { 0x20, 0x32, 0x30, 0x00 };
		
		//Check version identifier value of 0x20323030 XXX spreadsheet had this 0x20323030 but I believe this is wrong should be 0x20323000
		assertTrue(Arrays.equals(versionIdentifier, versionIdentifierValueToCheck));
	}
	
	//Extract record length, verify (??)
	@DisplayName("SP800-76.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_11(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
		
		assertTrue(biometricDataBlock.length >= 10);
		
		//Get bytes 9 and 10 of biometric data block to get record length.
		byte [] recordLength = Arrays.copyOfRange(biometricDataBlock, 8, 10);
		
		//Not sure what we actually need to test for this test case
		assertNotNull(recordLength);
		
		int biometricDataBlockLength  = (((recordLength[0] & 0xFF) << 8) | (recordLength[1] & 0xFF));
        
        //Confirm that the record length value is the same at the length of the leftover buffer
        assertTrue(biometricDataBlockLength == biometricDataBlock.length);
	}
	
	
	//Confirm that product identifier owner and product identifier type are non-zero and that MSBs identify vendor, LSBs identify minutia detection algorithm version
	@DisplayName("SP800-76.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_12(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
		
		assertTrue(biometricDataBlock.length >= 14);
		
		byte [] cBEFFProductIdentifierOwner  = Arrays.copyOfRange(biometricDataBlock, 10, 12);
		byte [] cBEFFProductIdentifierBype  = Arrays.copyOfRange(biometricDataBlock, 12,14);
		
		
		byte [] zeroBlock = { 0x00, 0x00 };
		
		assertTrue(!Arrays.equals(cBEFFProductIdentifierOwner, zeroBlock));
		assertTrue(!Arrays.equals(cBEFFProductIdentifierBype, zeroBlock));
	}
	
	//Confirm that capture equipment compliance has a value of 1000b
	@DisplayName("SP800-76.13 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_13(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
				
		//Not sure what does the 1000b value indicates that 4 bits and is it located on the 19th byte?
		assertTrue(biometricDataBlock.length >= 15);
		
		//Check the second byte of biometric data to confirm its is 1000b (0x80)
		assertTrue(Byte.compare(biometricDataBlock[14], (byte)0x80) == 0);
	}
	
	
	//Confirm that capture equipment id is non-NULL
	@DisplayName("SP800-76.14 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_14(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		//XXX Is it located on the 20th byte?
		assertTrue(biometricDataBlock.length >= 16);
		
		//Confirm that the 20th and 21st is not null
		assertTrue(Byte.compare(biometricDataBlock[14], (byte)0x00) != 0);
		assertTrue(Byte.compare(biometricDataBlock[15], (byte)0x00) != 0);
	}
	
	//Confirm that scanned image in X and scanned image in Y are non-zero (and obtained from enrollment records??)
	@DisplayName("SP800-76.15 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_15(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		//Is it located on the 20th byte?
		assertTrue(biometricDataBlock.length >= 21);

		byte [] scannedIimageInX  = Arrays.copyOfRange(biometricDataBlock, 16, 18);
		byte [] scannedIimageInY  = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		byte [] zeroBlock = { 0x00, 0x00 };
		
		//CHeck the values are not zero
		assertTrue(!Arrays.equals(scannedIimageInX, zeroBlock));
		assertTrue(!Arrays.equals(scannedIimageInY, zeroBlock));
		
		
	}
	
	//Confirm that X and Y resolution is 197
	@DisplayName("SP800-76.16 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_16(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
		assertTrue(biometricDataBlock.length >= 25);

		byte [] resolutionXBuff  = Arrays.copyOfRange(biometricDataBlock, 20, 22);
		byte [] resolutionYBuff  = Arrays.copyOfRange(biometricDataBlock, 22, 24);
		
		
		int resolutionX  = (((resolutionXBuff[0] & 0xFF) << 8) | (resolutionXBuff[1] & 0xFF));
		int resolutionY  = (((resolutionYBuff[0] & 0xFF) << 8) | (resolutionYBuff[1] & 0xFF));
		
        //Confirm the values are 197
        assertTrue(resolutionX == 197);     
        assertTrue(resolutionY == 197);
	}
	
	//Confirm that number of finger views is 2
	@DisplayName("SP800-76.17 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_17(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
		
		assertTrue(biometricDataBlock.length >= 26);

		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		
		assertNotNull(numberOfFingerViewsBuff);
		
		
		BigInteger numberOfFingers = new BigInteger(numberOfFingerViewsBuff);
        
        //Confirm nuimber of finger views is 2
        assertTrue(numberOfFingers.intValue() == 2);
	}
	
	//Confirm that reserved byte is set to 0
	@DisplayName("SP800-76.18 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_18(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 26);
		
		//Confirm that reserve byte is 0
		assertTrue(Byte.compare(biometricDataBlock[25], (byte)0x00) == 0);
	}
	
	//Confirm that Finger View Header has value 'A'
	@DisplayName("SP800-76.19 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_19(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		//This test needs to be removed
	}
	
	//Confirm that Finger View Position (0,14)
	@DisplayName("SP800-76.20 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_20(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 32);
		
		Byte b = new Byte(biometricDataBlock[32]);
		int fingerViewPosition = b.intValue();
        
        //Confirm Finger View Position is between 0 and 14
        assertTrue(fingerViewPosition > 0);
        assertTrue(fingerViewPosition < 15);
	}
	
	//If only 1 minutiae present for a finger, view number must be 0
	@DisplayName("SP800-76.21 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_21(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);

		assertTrue(biometricDataBlock.length >= 36);
		
		Byte b = new Byte(biometricDataBlock[33]);
		int viewNumber = b.intValue();
		
		b = new Byte(biometricDataBlock[36]);
		int numberOfMinutiae = b.intValue();
        
		if(numberOfMinutiae == 1) {
	        assertTrue(viewNumber == 0);
		} else {
	        assertTrue(viewNumber > 0);
		}
	}
	
	//Impression type must be 0 or 2
	@DisplayName("SP800-76.22 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_22(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);

		assertTrue(biometricDataBlock.length >= 34);
		
		Byte b = new Byte(biometricDataBlock[34]);
		int impressionType = b.intValue();
		
		//Confirm impression type is either 0 or 2
		assertTrue(impressionType == 0 || impressionType == 2);
	}
	
	//Number of minutia (0, 128)
	@DisplayName("SP800-76.23 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_23(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);		
		
		assertTrue(biometricDataBlock.length >= 36);
		
		Byte b = new Byte(biometricDataBlock[36]);
		int numberOfMinutia = b.intValue();
		
		//Confirm number of minutia is between 0 and 128
		assertTrue(numberOfMinutia > 0);
		assertTrue(numberOfMinutia < 128);
	}
	
	//Verify that minutiae type is 01b or 10b
	@DisplayName("SP800-76.24 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_24(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);		
		
		assertTrue(biometricDataBlock.length >= 36);
		
		Byte b = new Byte(biometricDataBlock[36]);
		int numberOfMinutia = b.intValue();
		
		int start = 37;
		for(int i = 0; i < numberOfMinutia; i++) {

			assertTrue(biometricDataBlock.length > start + 6);
			byte [] minutiaBuff  = Arrays.copyOfRange(biometricDataBlock, start, 6);
			
			boolean a = (1 == ((minutiaBuff[0] >> 1) & 1));
			boolean c = (1 == ((minutiaBuff[0] >> 1) & 1));
			
			assertTrue((a == false && c == true) || (a == true && c == false));
			
			start = start+6;
		}
		
		
	}
	
	//Verify that position is one of the valid x,y coordinate types in the original image 
	@DisplayName("SP800-76.25 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_25(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 36);
		
		Byte b = new Byte(biometricDataBlock[36]);
		int numberOfMinutia = b.intValue();
		
		int start = 37;
		for(int i = 0; i < numberOfMinutia; i++) {

			assertTrue(biometricDataBlock.length > start + 6);
			byte [] minutiaBuff  = Arrays.copyOfRange(biometricDataBlock, start, 6);
			
			//XXX Not entierly sure how to do the rest of this test
		}
	}
	
	//Verify that angle (0,179)
	@DisplayName("SP800-76.26 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_26(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 36);
		
		Byte b = new Byte(biometricDataBlock[36]);
		int numberOfMinutia = b.intValue();
		
		int start = 37;
		for(int i = 0; i < numberOfMinutia; i++) {

			assertTrue(biometricDataBlock.length > start + 6);
			byte [] minutiaBuff  = Arrays.copyOfRange(biometricDataBlock, start, 6);
			
			assertTrue(minutiaBuff.length >= 3);
			
			Byte bt = new Byte(minutiaBuff[3]);
			int angle = bt.intValue();
			
			//Confirm angle is between 0 and 179
			assertTrue(angle >= 0);
			assertTrue(angle <= 179);
		}
	}
	
	//Verify that quality (0,100)
	@DisplayName("SP800-76.27 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_27(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 36);
		
		Byte b = new Byte(biometricDataBlock[36]);
		int numberOfMinutia = b.intValue();
		
		int start = 37;
		for(int i = 0; i < numberOfMinutia; i++) {

			assertTrue(biometricDataBlock.length > start + 6);
			byte [] minutiaBuff  = Arrays.copyOfRange(biometricDataBlock, start, 6);
			
			assertTrue(minutiaBuff.length >= 4);
			
			Byte bt = new Byte(minutiaBuff[4]);
			int quality = bt.intValue();
			
			//Confirm quality between 0 and 100
			assertTrue(quality >= 0);
			assertTrue(quality <= 100);
		}
	}
	
	//Verify that extended data block length is 0
	@DisplayName("SP800-76.28 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_28(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 36);
		
		Byte b = new Byte(biometricDataBlock[36]);
		int numberOfMinutia = b.intValue();
		
		int start = 37;
		for(int i = 0; i < numberOfMinutia; i++) {

			assertTrue(biometricDataBlock.length > start + 6);
			byte [] minutiaBuff  = Arrays.copyOfRange(biometricDataBlock, start, 6);
			
			assertTrue(minutiaBuff.length >= 6);
			
			//Confirm that extended data block length is 0
			assertTrue(Byte.compare(minutiaBuff[4], (byte)0x00) == 0);
			assertTrue(Byte.compare(minutiaBuff[5], (byte)0x00) == 0);
		}
	}
	
	//Verify that format identifier is 0x46414300
	@DisplayName("SP800-76.29 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_29(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 4);
		
		//Get first 4 bytes of biometric data block to get format identifier.
		byte [] formatIdentifier = Arrays.copyOfRange(biometricDataBlock, 0, 4);
		byte [] formatIdentifierValueToCheck = { 0x46, 0x41, 0x43, 0x00 };
		
		//Check the 8th and 9th bytes of biometric data to confirm BDB Format Owner field has a value of 0x46414300
		assertTrue(Arrays.equals(formatIdentifier, formatIdentifierValueToCheck));
	}
	
	//Verify that version number is 0x30313000
	@DisplayName("SP800-76.30 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_30(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 8);
		
		//Get bytes 4 through 8 of biometric data block to get version identifier.
		byte [] versionIdentifier = Arrays.copyOfRange(biometricDataBlock, 4, 8);
		byte [] versionIdentifierValueToCheck = { 0x30, 0x31, 0x30, 0x00 };
		
		//Check version identifier value of 0x30313000
		assertTrue(Arrays.equals(versionIdentifier, versionIdentifierValueToCheck));
	}
	
	//Verify that record length < container size limit
	@DisplayName("SP800-76.31 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_31(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 12);
		
		//Get bytes 9 through 12 of biometric data block to get record length.
		byte [] recordLength = Arrays.copyOfRange(biometricDataBlock, 8, 12);
		
		assertNotNull(recordLength);
		
        ByteBuffer wrapped = ByteBuffer.wrap(recordLength);
        int biometricDataBlockLength = wrapped.getInt();
        
        //Confirm that the record length value is the same at the length of the leftover buffer
        assertTrue(biometricDataBlockLength == (biometricDataBlock.length - 12));
	}
	
	//Verify that number of facial images is 1
	@DisplayName("SP800-76.32 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_32(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 14);
		
		//Get bytes 9 through 12 of biometric data block to get record length.
		byte [] numberoffacesBuf = Arrays.copyOfRange(biometricDataBlock, 12, 14);
		
		assertNotNull(numberoffacesBuf);
		
        ByteBuffer wrapped = ByteBuffer.wrap(numberoffacesBuf);
        int numberoffaces = wrapped.getInt();
		
		assertTrue(numberoffaces == 1);
	}
	
	//Verify number of feature points is > 0
	@DisplayName("SP800-76.33 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_33(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 20);
		
		byte [] numberOfFeaturePointsBuf = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		assertNotNull(numberOfFeaturePointsBuf);
		
        ByteBuffer wrapped = ByteBuffer.wrap(numberOfFeaturePointsBuf);
        int numberOfFeaturePoints = wrapped.getInt();
		
		assertTrue(numberOfFeaturePoints > 0);
	}
	
	//Verify that facial image type is 1
	@DisplayName("SP800-76.34 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_34(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 20);
		
		byte [] numberOfFeaturePointsBuf = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		assertNotNull(numberOfFeaturePointsBuf);
		
        ByteBuffer wrapped = ByteBuffer.wrap(numberOfFeaturePointsBuf);
        int numberOfFeaturePoints = wrapped.getInt();
        
        
        int offset = 12 + numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 1);
        
        Byte bt = new Byte(biometricDataBlock[20 + offset]);
		int facialImageType  = bt.intValue();
		
		assertTrue(facialImageType == 1);
	}
	
	//Verify that image data type is 0 or 1
	@DisplayName("SP800-76.35 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_35(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 20);
		
		byte [] numberOfFeaturePointsBuf = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		assertNotNull(numberOfFeaturePointsBuf);
		
        ByteBuffer wrapped = ByteBuffer.wrap(numberOfFeaturePointsBuf);
        int numberOfFeaturePoints = wrapped.getInt();
        
        
        int offset = 12 + numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 2);
        
        Byte bt = new Byte(biometricDataBlock[20 + offset +1]);
		int facialImageType  = bt.intValue();
		
		assertTrue(facialImageType == 1 || facialImageType == 0);
	}
	
	//Verify that image color space is 1
	@DisplayName("SP800-76.36 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_36(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 20);
		
		byte [] numberOfFeaturePointsBuf = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		assertNotNull(numberOfFeaturePointsBuf);
		
        ByteBuffer wrapped = ByteBuffer.wrap(numberOfFeaturePointsBuf);
        int numberOfFeaturePoints = wrapped.getInt();
        
        
        int offset = 12 + numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 6);
        
        Byte bt = new Byte(biometricDataBlock[20 + offset + 5]);
		int colorSpace  = bt.intValue();
		
		assertTrue(colorSpace == 1);
	}
	
	//Verify that source type is 2 or 6
	@DisplayName("SP800-76.37 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_37(String oid, TestReporter reporter) {
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
			
		byte[] biometricDataBlock = ((CardholderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock);
							
		assertTrue(biometricDataBlock.length >= 20);
		
		byte [] numberOfFeaturePointsBuf = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		assertNotNull(numberOfFeaturePointsBuf);
		
        ByteBuffer wrapped = ByteBuffer.wrap(numberOfFeaturePointsBuf);
        int numberOfFeaturePoints = wrapped.getInt();
        
        
        int offset = 12 + numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 7);
        
        Byte bt = new Byte(biometricDataBlock[20 + offset + 7]);
		int sourceType  = bt.intValue();
		
		assertTrue(sourceType == 2 || sourceType == 6);
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
