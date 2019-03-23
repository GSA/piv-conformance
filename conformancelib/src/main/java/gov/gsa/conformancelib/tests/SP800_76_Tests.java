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
	
	//Patron Header Version is 0x03
	@DisplayName("SP800-76.5 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
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
			
			
			//Confirm Card Holder Facial Image object length equals sum of CBEFF header length + BDB length + SB length
			assertTrue(biometricData.length == (88 + biometricDataBlockLength + signatureDataBlockLength));

		 }
	}
	
	//Extract contents of format identifier, confirm value 0x464D5200
	@DisplayName("SP800-76.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
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
		
		//Get first 4 bytes of biometric data block to get format identifier.  XXX Confirm that the first 4 bytes of biometric data block is the format identifier
		byte [] formatIdentifier = Arrays.copyOfRange(biometricDataBlock, 0, 4);
		byte [] formatIdentifierValueToCheck = { 0x46, 0x4D, 0x52, 0x00 };
		
		//Check the 8th and 9th bytes of biometric data to confirm BDB Format Owner field has a value of 0x001B
		assertTrue(Arrays.equals(formatIdentifier, formatIdentifierValueToCheck));
	}
	
	//Extract contents of version identifier, confirm value 0x20323030
	@DisplayName("SP800-76.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
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
		
		//Get bytes 4 through 8 of biometric data block to get version identifier.  XXX Confirm that the next 4 bytes of biometric data block is the version identifier
		byte [] versionIdentifier = Arrays.copyOfRange(biometricDataBlock, 4, 8);
		byte [] versionIdentifierValueToCheck = { 0x20, 0x32, 0x30, 0x30 };
		
		//Check the 8th and 9th bytes of biometric data to confirm BDB Format Owner field has a value of 0x001B
		assertTrue(Arrays.equals(versionIdentifier, versionIdentifierValueToCheck));
	}
	
	//Extract record length, verify (??)
	@DisplayName("SP800-76.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
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
		
		//Get bytes 9 and 10 of biometric data block to get record length.  XXX Confirm that bytes 9 and 10 of biometric data block are the record length
		byte [] recordLength = Arrays.copyOfRange(biometricDataBlock, 8, 10);
		
		//Not sure what we actually need to test for this test case
		assertNotNull(recordLength);
	}
	
	
	//Confirm that product identifier owner and product identifier type are non-zero and that MSBs identify vendor, LSBs identify minutia detection algorithm version
	@DisplayName("SP800-76.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
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
		
		assertTrue(biometricDataBlock.length >= 18);
		
		//XXX Not clear to me if each field is 4 bytes or each field is 2 bytes 
		byte [] cBEFFProductIdentifierOwner  = Arrays.copyOfRange(biometricDataBlock, 10, 14);
		byte [] cBEFFProductIdentifierBype  = Arrays.copyOfRange(biometricDataBlock, 14,18);
		
		
		byte [] zeroBlock = { 0x00, 0x00, 0x00, 0x00 };
		
		assertTrue(!Arrays.equals(cBEFFProductIdentifierOwner, zeroBlock));
		assertTrue(!Arrays.equals(cBEFFProductIdentifierBype, zeroBlock));
		
		//Not sure how to check that MSBs identify vendor, LSBs identify minutia detection algorithm version
	}
	
	//Confirm that capture equipment compliance has a value of 1000b
	@DisplayName("SP800-76.13 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
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
				
		//Not sure what does the 1000b value indicates that 4 bits?
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
