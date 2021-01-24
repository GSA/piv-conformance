package gov.gsa.pivconformance.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.cardlib.card.client.CardHolderBiometricData;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterUtils;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;

public class SP800_76_Tests {
	static Logger s_logger = org.slf4j.LoggerFactory.getLogger(SP800_76_Tests.class);
	
	//BDB length field is non-zero
	@DisplayName("SP800-76.1 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_1(String oid, TestReporter reporter) {
		
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		 if (biometricData != null && biometricData.length > 8) {

             //Get Biometric data block (BDB) Length
             byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 2, 6);
             

     		assertNotNull(biometricDataBlockLengthBytes, "Biometric data block length bytes is absent in CardHolderBiometricData object");
     		
     		//Convert Biometric data block (BDB) Length byte[] value to int
            ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
            int biometricDataBlockLength = wrapped.getInt();
            
            assertTrue(biometricDataBlockLength > 0, "Biometric data block length is not greater than 0");
		 }
	}

	
	//Recorded length matches actual length
	@DisplayName("SP800-76.2 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_2(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		
		 if (biometricData != null && biometricData.length > 8) {

             //Get Biometric data block (BDB) Length
             byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 2, 6);
             

     		assertNotNull(biometricData, "Biometric data block length is absent in CardHolderBiometricData object");
     		
     		//Convert Biometric data block (BDB) Length byte[] value to int
            ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
            int biometricDataBlockLength = wrapped.getInt();
            
            assertTrue(biometricDataBlockLength > 0);
            
            assertTrue(biometricDataBlock.length == biometricDataBlockLength,  "Biometric data block length does not matche actual length");
            
		 }
	}
	
	//SB length field is non-zero
	@DisplayName("SP800-76.3 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_3(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		 if (biometricData != null && biometricData.length > 8) {
			 
             //Get Signature block (SB) Length
             byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);
             

     		assertNotNull(signatureDataBlockLengthBytes, "Signature data block length is absent in CardHolderBiometricData object");
     		
     		 //Convert Signature block (SB) Length byte[] value to int
     		ByteBuffer wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
            int signatureDataBlockLength = wrapped.getShort();
            
            assertTrue(signatureDataBlockLength > 0, "Signature data block length is not greater than 0");
		 }
	}
	
	//Card Holder Fingerprint object length equals sum of CBEFF header length + BDB length + SB length
	@DisplayName("SP800-76.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_4(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		 if (biometricData != null && biometricData.length > 8) {
			 
			//Get Biometric data block (BDB) Length
			byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 2, 6);
			
			assertNotNull(biometricData, "Biometric data block length  is absent in CardHolderBiometricData object");
			
			//Convert Biometric data block (BDB) Length byte[] value to int
			ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
			int biometricDataBlockLength = wrapped.getInt();
			           
			//Get Signature block (SB) Length
			byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);	
			assertNotNull(signatureDataBlockLengthBytes, "Signature data block length is absent in CardHolderBiometricData object");
			
			//Convert Signature block (SB) Length byte[] value to int
			wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
			int signatureDataBlockLength = wrapped.getShort();
			
			assertTrue(biometricData.length == (88 + biometricDataBlockLength + signatureDataBlockLength),  "Signature data block length does not matche actual length");

		 }
	}
	
	//Patron Header Version is 0x03
	@DisplayName("SP800-76.5 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_5(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length > 1);
		
		//Check the first byte of biometric data to confirm its is 0x03
		assertTrue(Byte.compare(biometricData[0], (byte)0x03) == 0, "First byte of biometrict data is not 0x03");
	}
	
	//SBH security options field has value b00001101 (0x0D)
	@DisplayName("SP800-76.6 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_6(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length > 2);
		
		//Check the second byte of biometric data to confirm its is b00001101 (0x0D)
		assertTrue(Byte.compare(biometricData[1], (byte)0x0D) == 0, "Second byte of biometric data is not b00001101 (0x0D)" );
	}
	
	//BDB Format Owner field has a value of 0x001B
	@DisplayName("SP800-76.7 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_7(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length >= 10);
		
		//Check the 8th and 9th bytes of biometric data to confirm BDB Format Owner field has a value of 0x001B
		assertTrue(Byte.compare(biometricData[8], (byte)0x00) == 0, "BDB Format Owner field has a value is not 0x001B");
		assertTrue(Byte.compare(biometricData[9], (byte)0x1B) == 0, "BDB Format Owner field has a value is not 0x001B");
	}
	
	//Card Holder Facial Image object length equals sum of CBEFF header length + BDB length + SB length
	@DisplayName("SP800-76.8 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_8(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		 if (biometricData != null && biometricData.length > 8) {
			 
			//Get Biometric data block (BDB) Length
			byte[] biometricDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 2, 6);
			
			assertNotNull(biometricData, "Biometric data block length  is absent in CardHolderBiometricData object");
			
			//Convert Biometric data block (BDB) Length byte[] value to int
			ByteBuffer wrapped = ByteBuffer.wrap(biometricDataBlockLengthBytes);
			int biometricDataBlockLength = wrapped.getInt();
			           
			//Get Signature block (SB) Length
			byte[] signatureDataBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);	
			assertNotNull(signatureDataBlockLengthBytes, "Biometric data block length  is absent in CardHolderBiometricData object");
			
			//Convert Signature block (SB) Length byte[] value to int
			wrapped = ByteBuffer.wrap(signatureDataBlockLengthBytes);
			int signatureDataBlockLength = wrapped.getShort();
			
			
			//Confirm Card Holder Facial Image object length equals sum of CBEFF header length + BDB length + SB length
			assertTrue(biometricData.length == (88 + biometricDataBlockLength + signatureDataBlockLength), "Facial Image object length does Not equal sum of CBEFF header length + BDB length + SB length");

		 }
	}
	
	//Extract contents of format identifier, confirm value 0x464D5200
	@DisplayName("SP800-76.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_9(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		
		assertTrue(biometricDataBlock.length >= 4);
		
		//Get first 4 bytes of biometric data block to get format identifier.
		byte [] formatIdentifier = Arrays.copyOfRange(biometricDataBlock, 0, 4);
		byte [] formatIdentifierValueToCheck = { 0x46, 0x4D, 0x52, 0x00 };
		
		//Check  format identifier value of 0x464D5200
		assertTrue(Arrays.equals(formatIdentifier, formatIdentifierValueToCheck), "Fingerprint format identifier value is not 0x464D5200");
	}
	
	//Extract contents of version identifier, confirm value 0x20323030
	@DisplayName("SP800-76.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_10(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		
		assertTrue(biometricDataBlock.length >= 8);
		
		//Get bytes 4 through 8 of biometric data block to get version identifier.
		byte [] versionIdentifier = Arrays.copyOfRange(biometricDataBlock, 4, 8);
		byte [] versionIdentifierValueToCheck = { 0x20, 0x32, 0x30, 0x00 };
		
		assertTrue(Arrays.equals(versionIdentifier, versionIdentifierValueToCheck), "Fingerprint version identifie value is not 0x20323030");
	}
	
	//Extract record length, verify 26 <= L <= 1574
	@DisplayName("SP800-76.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_11(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		
		assertTrue(biometricDataBlock.length >= 10);
		
		//Get bytes 9 and 10 of biometric data block to get record length.
		byte [] recordLength = Arrays.copyOfRange(biometricDataBlock, 8, 10);
	
		int biometricDataBlockLength  = (((recordLength[0] & 0xFF) << 8) | (recordLength[1] & 0xFF));
		
		//BDB length must be between 26 and 1574
        assertTrue(biometricDataBlockLength >= 26 && biometricDataBlockLength <= 1574, "Fingerprint recod length is not 26 <= L <= 1574");
        //Confirm that the record length value is the same at the length of the leftover buffer
        assertTrue(biometricDataBlockLength == biometricDataBlock.length, "Fingerprint recod length does not match leftover buffer length");
	}
	
	
	//Confirm that product identifier owner and product identifier type are non-zero and that MSBs identify vendor, LSBs identify minutia detection algorithm version
	@DisplayName("SP800-76.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_12(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		
		assertTrue(biometricDataBlock.length >= 14);
		
		byte [] cBEFFProductIdentifierOwner  = Arrays.copyOfRange(biometricDataBlock, 10, 12);
		byte [] cBEFFProductIdentifierBype  = Arrays.copyOfRange(biometricDataBlock, 12,14);
		
		
		byte [] zeroBlock = { 0x00, 0x00 };
		
		assertTrue(!Arrays.equals(cBEFFProductIdentifierOwner, zeroBlock), "Fingerprint product identifier owner and product identifier type are zero");
		assertTrue(!Arrays.equals(cBEFFProductIdentifierBype, zeroBlock), "Fingerprint product identifier owner and product identifier type are zero");
	}
	
	//Confirm that capture equipment compliance has a value of 1000b
	/*
	 * From ANSI-378:
	 * 6.4.5 Capture Equipment Compliance
	 * Four bits are reserved to indicate compliance of the image capture equipment used to originally acquire the image
	 * from which the minutiae were extracted. The most significant bit, if set to a 1, shall indicate that the equipment
	 * was certified to comply with Appendix F (IAFIS Image Quality Specification, January 29, 1999) of CJIS-RS-0010,
	 * the Federal Bureau of Investigation's Electronic Fingerprint Transmission Specification. The other three bits are
	 * reserved for future compliance indicators.
	 */
	@DisplayName("SP800-76.13 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_13(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		assertTrue(biometricDataBlock.length >= 15);
		
		//Check the second byte of biometric data to confirm its high order bit is set 1000b (0x80)
		assertTrue((biometricDataBlock[14] & 0xF0) == 0x80, "Fingerprint capture equipment compliance value is not 1000b (0x80)");
	}
	
	
	//Confirm that capture equipment id is non-NULL
	/*
	 * 
	 * 6.4.6 Capture Equipment ID
	 * The capture equipment ID shall be recorded in twelve bits. A value of all zeros will be acceptable and will
	 * indicate that the capture equipment ID is unreported. The value of this field is determined by the vendor. 
	 * Applications developers may obtain the values for these codes from the vendor. 
	 */
	@DisplayName("SP800-76.14 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_14(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 16);

		//Confirm that the first 12 bits are not null
		byte[] ceiBytes = Arrays.copyOfRange(biometricDataBlock, 14, 16);
		ByteBuffer wrapped = ByteBuffer.wrap(ceiBytes);
		short cei = wrapped.getShort();
		cei &= 0x0FFF;
		
		assertTrue(cei > 0, "Fingerprint capture equipment id is NULL");
	}
	
	//Confirm that scanned image in X are non-zero (and obtained from enrollment records??)
	@DisplayName("SP800-76.15a test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_15a(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		//Is it located on the 20th byte?
		assertTrue(biometricDataBlock.length >= 21);

		byte [] scannedIimageInX  = Arrays.copyOfRange(biometricDataBlock, 16, 18);
		// moved due to atom splitting
		// byte [] scannedIimageInY  = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		byte [] zeroBlock = { 0x00, 0x00 };
		
		//Check the values are not zero
		assertTrue(!Arrays.equals(scannedIimageInX, zeroBlock), "Fingerprint scanned image in X is zero");
		
		
	}
	
	//Confirm that scanned image in Y are non-zero (and obtained from enrollment records??)
	@DisplayName("SP800-76.15b test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_15b(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		//Is it located on the 20th byte?
		assertTrue(biometricDataBlock.length >= 21);

		// removed due to atom splitting
		//byte [] scannedIimageInX  = Arrays.copyOfRange(biometricDataBlock, 16, 18);
		byte [] scannedIimageInY  = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		byte [] zeroBlock = { 0x00, 0x00 };
		
		//CHeck the values are not zero
		assertTrue(!Arrays.equals(scannedIimageInY, zeroBlock), "Fingerprint scanned image in Y is zero");
		
		//Width of the Size of Scanned Image in x direction is the larger of the widths of the two input
		assertTrue(true); //TODO: Need to grab both FMRs and ensure that the one with the largest X size matches
		
		//Height of the Size of Scanned Image in y direction is the larger of the heights of the two input images.
		assertTrue(true);//TODO: Need to grab both FMRs and ensure that the one with the largest Y size matches
	}
	
	//Confirm that X and Y resolution is 197
	@DisplayName("SP800-76.16 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_16(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		assertTrue(biometricDataBlock.length >= 25);

		byte [] resolutionXBuff  = Arrays.copyOfRange(biometricDataBlock, 20, 22);
		byte [] resolutionYBuff  = Arrays.copyOfRange(biometricDataBlock, 22, 24);
		
		
		int resolutionX  = (((resolutionXBuff[0] & 0xFF) << 8) | (resolutionXBuff[1] & 0xFF));
		int resolutionY  = (((resolutionYBuff[0] & 0xFF) << 8) | (resolutionYBuff[1] & 0xFF));
		
        //Confirm the values are 197
        assertTrue(resolutionX == 197, "Fingerprint X resolution is not 197");     
        assertTrue(resolutionY == 197, "Fingerprint Y resolution is not 197");    
	}
	
	//Confirm that number of finger views is 2
	@DisplayName("SP800-76.17 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_17(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		
		assertTrue(biometricDataBlock.length >= 26);

		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		
		assertNotNull(numberOfFingerViewsBuff);
		
		
		BigInteger numberOfFingers = new BigInteger(numberOfFingerViewsBuff);
        
        //Confirm nuimber of finger views is 2
        assertTrue(numberOfFingers.intValue() == 2, "Number of finger views does not equal 2");
	}
	
	//Confirm that reserved byte is set to 0
	@DisplayName("SP800-76.18 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_18(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 26);
		
		//Confirm that reserve byte is 0
		assertTrue(Byte.compare(biometricDataBlock[25], (byte)0x00) == 0, "Fingerprint reverse byte is not 0");
	}
	
	//Confirm that Finger View Header has value 'A'
	@DisplayName("SP800-76.19 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_19(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		//This test needs to be removed
	}
	
	//Confirm that Finger View Position (0,14)
	@DisplayName("SP800-76.20 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_20(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		        
		assertTrue(biometricDataBlock.length >= 27);
							
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();
        
        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			int fingerPosition = b1.intValue();
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
			
			

	        assertTrue(fingerPosition >= 0, "Finger porition less than 0");
	        assertTrue(fingerPosition <= 14, "Finger porition greater than 14");

	        offset = offset+6+numberOfMinutiae*6;
        }
	}
	
	//If only 1 minutiae present for a finger, view number must be 0
	@DisplayName("SP800-76.21 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_21(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		        
		assertTrue(biometricDataBlock.length >= 27);
							
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();

        
        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			int viewNumber = ((biometricDataBlock[offset+1] & 0xF0) >> 4);
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
			
			
			if(numberOfMinutiae == 1)
	        	assertTrue(viewNumber == 0, "View number is not 0");

	        offset = offset+6+numberOfMinutiae*6;
        }
	}
	
	//Impression type must be 0 or 2
	@DisplayName("SP800-76.22 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_22(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");

		assertTrue(biometricDataBlock.length >= 27);
		
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();
        
        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			int impressionType = ((biometricDataBlock[offset+1] & 0x0F) << 8);
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
			
			
			//Confirm impression type is 0 or 2
	        assertTrue(impressionType == 0 || impressionType == 2, "Fingerprint imprssion is not 0 or 2");

	        offset = offset+6+numberOfMinutiae*6;
        }
	}
	
	//Number of minutia (0, 128)
	@DisplayName("SP800-76.23 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_23(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
				
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");		
		        
		assertTrue(biometricDataBlock.length >= 29);
							
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();

        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
	        
	        //Confirm number of minutiae is between 0 and 128
	        assertTrue(numberOfMinutiae >= 0, "Number of minutiae is less than 0");
	        assertTrue(numberOfMinutiae <= 128, "Number of minutiae is greater than 128");

	        offset = offset+6+numberOfMinutiae*6;
        }
	}
	
	//Minutiae Type value shall be 01b, 10b, or 00b.
	@DisplayName("SP800-76.24 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_24(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");		
		
		assertTrue(biometricDataBlock.length >= 29);
		
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();

        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
	        
			for (int minutiae = 0; minutiae < numberOfMinutiae; minutiae++) {
				
				int minType = ((biometricDataBlock[offset+4] & 0xC0) >> 6);
			
				assertTrue(minType == 0 || minType == 1 || minType == 2, "Minutiae Type value is not 0, 1 or 2");
				
				offset = offset+6;
			}

	        offset = offset+6;
        }
	}
	
	//Verify that position is one of the valid x,y coordinate types in the original image 
	@DisplayName("SP800-76.25 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_25(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 29);
		
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();

        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
	        
			for (int minutiae = 0; minutiae < numberOfMinutiae; minutiae++) {
				
				
				
				//XXX Not sure how to check position
				
				offset = offset+6;
			}

	        offset = offset+6;
        }
	}
	
	//Verify that angle (0,179)
	@DisplayName("SP800-76.26 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_26(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 29);
		
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();

        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
	        
			for (int minutiae = 0; minutiae < numberOfMinutiae; minutiae++) {

				int angle = biometricDataBlock[offset+8] & 0xFF;
				
				assertTrue(angle >= 0 && angle <= 179, "Angle is not between 0 and 179");
				offset = offset+6;
			}

	        offset = offset+6;
        }
	}
	
	//Verify that quality (0,100)
	@DisplayName("SP800-76.27 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_27(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 29);
		
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();

        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
	        
			for (int minutiae = 0; minutiae < numberOfMinutiae; minutiae++) {

				int quality = biometricDataBlock[offset+9] & 0xFF;
				
				assertTrue(quality >= 0 && quality <= 100, "Quality is not between 0 and 100");
				offset = offset+6;
			}

	        offset = offset+6;
        }
	}
	
	//Verify that extended data block length is 0
	@DisplayName("SP800-76.28 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_28(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 29);
		
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();

        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			b3.intValue();
			int numberOfMinutiae = b4.intValue();
	        
			byte [] zeroBlock = { 0x00, 0x00 };
			
			byte [] extendedDataBlockLength  = Arrays.copyOfRange(biometricDataBlock, offset+numberOfMinutiae*6+3, offset+numberOfMinutiae*6+3+2);
			
			assertTrue(Arrays.equals(extendedDataBlockLength, zeroBlock), "Extended data block length is not 0");
			
	        offset = offset+6+numberOfMinutiae*6;
        }
	}
	
	//Verify that format identifier is 0x46414300
	@DisplayName("SP800-76.29 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_29(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 4);
		
		//Get first 4 bytes of biometric data block to get format identifier.
		byte [] formatIdentifier = Arrays.copyOfRange(biometricDataBlock, 0, 4);
		byte [] formatIdentifierValueToCheck = { 0x46, 0x41, 0x43, 0x00 };
		
		//Check the 8th and 9th bytes of biometric data to confirm BDB Format Owner field has a value of 0x46414300
		assertTrue(Arrays.equals(formatIdentifier, formatIdentifierValueToCheck), "Facial image format identifier is not 0x46414300");
	}
	
	//Verify that version number is 0x30313000
	@DisplayName("SP800-76.30 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_30(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 8);
		
		//Get bytes 4 through 8 of biometric data block to get version identifier.
		byte [] versionIdentifier = Arrays.copyOfRange(biometricDataBlock, 4, 8);
		byte [] versionIdentifierValueToCheck = { 0x30, 0x31, 0x30, 0x00 };
		
		//Check version identifier value of 0x30313000
		assertTrue(Arrays.equals(versionIdentifier, versionIdentifierValueToCheck), "Facial image version identifier is not 0x30313000");
	}
	
	//Verify that record length < container size limit
	@DisplayName("SP800-76.31 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_31(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 12);
		
		//Get bytes 9 through 12 of biometric data block to get record length.
		byte [] recordLength = Arrays.copyOfRange(biometricDataBlock, 8, 12);
		
		assertNotNull(recordLength);
		
        ByteBuffer wrapped = ByteBuffer.wrap(recordLength);
        int biometricDataBlockLength = wrapped.getInt();
        
        //Confirm that the record length value is the same at the length of the leftover buffer
        assertTrue(biometricDataBlockLength == biometricDataBlock.length, "Facial image record length value is not the same at the length of the leftover buffer");
	}
	
	//Verify that number of facial images is 1
	@DisplayName("SP800-76.32 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_32(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 14);
		
		//Get bytes 9 through 12 of biometric data block to get record length.
		byte [] numberoffacesBuf = Arrays.copyOfRange(biometricDataBlock, 12, 14);
		
		assertNotNull(numberoffacesBuf);
		
        BigInteger numberoffaces = new BigInteger(numberoffacesBuf);
        
		assertTrue(numberoffaces.intValue() == 1, "Number of faces is not 1");
	}
	
	//Verify number of feature points is > 0
	@DisplayName("SP800-76.33 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_33(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 20);
		
		byte [] numberOfFeaturePointsBuf = Arrays.copyOfRange(biometricDataBlock, 18, 20);
		
		assertNotNull(numberOfFeaturePointsBuf);
		
        int numberOfFeaturePoints = ((biometricDataBlock[18] << 8 & 0xFF) | biometricDataBlock[19] & 0xFF);
		
        //XXX Find out why test cards have 0 feature points
		assertTrue(numberOfFeaturePoints > 0, "Number of feature point is not greater than 0");
	}
	
	//Verify that facial image type is 1
	@DisplayName("SP800-76.34 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_34(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 20);
		
		int numberOfFeaturePoints = ((biometricDataBlock[18] << 8 & 0xFF) | biometricDataBlock[19] & 0xFF);
        
		int offset = 14;
		if(numberOfFeaturePoints > 0)
			offset = offset+ numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 1);
        
		int facialImageType  = biometricDataBlock[20 + offset] & 0xFF;
		
		assertTrue(facialImageType == 1, "Facial image type is not 1");
	}
	
	//Verify that image data type is 0 or 1
	@DisplayName("SP800-76.35 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_35(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 20);
		
		int numberOfFeaturePoints = ((biometricDataBlock[18] << 8 & 0xFF) | biometricDataBlock[19] & 0xFF);
        
		int offset = 15;
		if(numberOfFeaturePoints > 0)
			offset = offset+ numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 1);
        
		int facialImageDataType  = biometricDataBlock[20 + offset] & 0xFF;
		
		assertTrue(facialImageDataType == 1 || facialImageDataType == 0, "Facial image data type is not 1 or 0");
	}
	
	//Verify that image color space is 1
	@DisplayName("SP800-76.36 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_36(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 20);
		
		int numberOfFeaturePoints = ((biometricDataBlock[18] << 8 & 0xFF) | biometricDataBlock[19] & 0xFF);
        
		int offset = 20;
		if(numberOfFeaturePoints > 0)
			offset = offset+ numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 1);
        
		int imageColorSpace  = biometricDataBlock[20 + offset] & 0xFF;
		
		assertTrue(imageColorSpace == 1, "Image color space is not 1");
	}
	
	//Verify that source type is 2 or 6
	@DisplayName("SP800-76.37 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FacialImageTestProvider")
	void sp800_76Test_37(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
							
		assertTrue(biometricDataBlock.length >= 20);
		
		int numberOfFeaturePoints = ((biometricDataBlock[18] << 8 & 0xFF) | biometricDataBlock[19] & 0xFF);
        
		int offset = 21;
		if(numberOfFeaturePoints > 0)
			offset = offset+ numberOfFeaturePoints*8;
        
        assertTrue(biometricDataBlock.length >= 20 + offset + 1);
        
		int sourceType  = biometricDataBlock[20 + offset] & 0xFF;
		
		assertTrue(sourceType == 2 || sourceType == 6, "Facial image source type is not 2 or 6");
	}
	
	
	//Validate that the BDB Format Type is set to the appropriate value
	@DisplayName("SP800-76.38 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_76_BiometricParamTestProvider1")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_76Test_38(String oid, String paramsString, TestReporter reporter) {
		@SuppressWarnings("unchecked")
		HashMap<String, List<String>> mp = (HashMap) ParameterUtils.MapFromString(paramsString);
		assertNotNull(mp);
		boolean foundContainer = false;
		for (Map.Entry<String,List<String>> entry : mp.entrySet()) {
	    	Map.Entry<String,List<String>> pair = entry;	    	
	        String containerName = pair.getKey();
	        if (containerName.compareTo(APDUConstants.containerOidToNameMap.get(oid)) == 0) {
	        	foundContainer = true;
		        s_logger.debug("called with oid parameter {} and container name {}", oid, containerName);
		        List<String> valueStr =  pair.getValue();
				String containerOid = APDUConstants.getStringForFieldNamed(containerName);
				assertNotNull(containerOid, "Unable to resolve container name: " + containerName);
				assertTrue(valueStr.size() == 1, "Illegal number of values for SP800-76.38 test: " + valueStr.size());
				boolean isMandatory = APDUConstants.isContainerMandatory(containerOid);
				// if the object is not mandatory and is not present, the test is done
				if(!isMandatory && !AtomHelper.isDataObjectPresent(containerOid, true)) {
					s_logger.info("Optional container {} ({}) is absent from the card.", containerName, containerOid);
					continue;
				} else {
					s_logger.info("Optional container {} ({}) is present on the card. Proceeding with test.", containerName, containerOid);
				}
	
				int value = 0;
				try {
					value = Integer.parseInt(valueStr.get(0));
				} catch(NumberFormatException e) {
					fail(e);
				}
				
				PIVDataObject o = AtomHelper.getDataObject(containerOid);
					
				byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
				
				//Make sure biometric data is present
				assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
				
				assertTrue(biometricData.length >= 12, "Biometric data must be at least 12 bytes long");
				
				//Check format type field has the right value 
				
				int type  = (((biometricData[10] & 0xFF) << 8) | (biometricData[11] & 0xFF));
				
				assertTrue(type == value, "Invalid type in biometric data. Got " + type + ", expected " + value);
		    }
		}
		if (!foundContainer) {
			String msg = "Invalid container specified in parameter for this test case";
			s_logger.error(msg);
		}
	}
	
	//Validate that that the creation date in the PIV Patron Format is encoded in 8 bytes using a binary representation of YYYYMMDDhhmmssZ
	@DisplayName("SP800-76.39 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_39(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length >= 21);
		
		
		byte[] biometricCreationDate = Arrays.copyOfRange(biometricData, 12, 12+8);
		StringBuilder str = new StringBuilder(); 
		
		for (int i = 0; i < biometricCreationDate.length-1; i++) {
			
			int num = biometricCreationDate[i] & 0xFF;
			
			if(num < 10  )
				str.append("0");
			str.append(num);
		}
		assertTrue(biometricCreationDate[biometricCreationDate.length-1] == 'Z');
		System.out.print(str);
		assertNotNull(biometricCreationDate);
				
		//Get the creation date value and parse it into a Date object using "YYYYMMDDhhmmssZ" format
        try {
			Date date = new SimpleDateFormat("yyyyMMddHHmmss").parse(str.toString());
			
			assertNotNull(date, "Unable to create date object from biometric creation date value " + str.toString());
		} catch (ParseException e) {
			fail(e);
		}
	}
	
	
	//Validate date encoding on Validity Period in PIV Patron Format
	@DisplayName("SP800-76.40 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_40(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length >= 37);
		
		
		byte[] biometricValidityPeriodDate1 = Arrays.copyOfRange(biometricData, 20, 20+8);
		byte[] biometricValidityPeriodDate2 = Arrays.copyOfRange(biometricData, 28, 36);
		
		assertNotNull(biometricValidityPeriodDate1);
		assertNotNull(biometricValidityPeriodDate2);
		
		StringBuilder str1 = new StringBuilder(); 
		
		for (int i = 0; i < biometricValidityPeriodDate1.length-1; i++) {
			
			int num = biometricValidityPeriodDate1[i] & 0xFF;
			
			if(num < 10  )
				str1.append("0");
			str1.append(num);
		}
		assertTrue(biometricValidityPeriodDate1[biometricValidityPeriodDate1.length-1] == 'Z');
		
		StringBuilder str2 = new StringBuilder(); 
		
		for (int i = 0; i < biometricValidityPeriodDate2.length-1; i++) {
			
			int num = biometricValidityPeriodDate2[i] & 0xFF;
			
			if(num < 10  )
				str2.append("0");
			str2.append(num);
		}
		assertTrue(biometricValidityPeriodDate2[biometricValidityPeriodDate2.length-1] == 'Z');
		
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
        try {
			Date date = new SimpleDateFormat("yyyyMMddHHmmss").parse(str1.toString());
			
			assertNotNull(date, "Unable to create date object from biometric creation date value " + str1.toString());
		} catch (ParseException e) {
			fail(e);
		}
        
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
        try {
			Date date = new SimpleDateFormat("yyyyMMddHHmmss").parse(str2.toString());
			
			assertNotNull(date, "Unable to create date object from biometric creation date value " + str2.toString());
		} catch (ParseException e) {
			fail(e);
		}
	}
	
	//Validate that that Biometric Type has the right value
		@DisplayName("SP800-76.41 test")
		//@ParamterizedTest(name = "{index} => oid = {0}")
		//@ParameterizedTest(name = "{index}foo")
		//@MethodSource("sp800_76_BiometricParamTestProvider2")
		// for some tests, this seems to need to be fully qualified to avoid a conflict with the TestReporter arguments provider
		@ArgumentsSource(gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider.class)
		void sp800_76Test_41(String oid, String paramsString, TestReporter reporter) {
			Map<String, List<String>> mp = ParameterUtils.MapFromString(paramsString);
			assertNotNull(mp);
			Iterator<Map.Entry<String,List<String>>> it = mp.entrySet().iterator();
			boolean foundContainer = false;
		    while (it.hasNext()) {
		    	Map.Entry<String,List<String>> pair = it.next();	    	
		        String containerName = pair.getKey();
		        if (containerName.compareTo(APDUConstants.containerOidToNameMap.get(oid)) == 0) {
		        	foundContainer = true;
			        List<String> valueStr =  pair.getValue();
					assertTrue(valueStr.size() == 1, "Illegal number of values for SP800-76.41 test: " + valueStr.size());
					String containerOid = APDUConstants.getStringForFieldNamed(containerName);
					assertNotNull(containerOid);
					
					boolean isMandatory = APDUConstants.isContainerMandatory(containerOid);
					// if the object is not mandatory and is not present, the test is done
					if(!isMandatory && !AtomHelper.isDataObjectPresent(containerOid, true)) {
						s_logger.info("Optional container {} ({}) is absent from the card.", containerName, containerOid);
						continue;
					} else {
						s_logger.info("Optional container {} ({}) is present on the card. Proceeding with test.", containerName, containerOid);
					}
	
					int value = 0;
					try {
						value = Integer.parseInt(valueStr.get(0));
					} catch(NumberFormatException e) {
						fail(e);
					}
	
					PIVDataObject o = AtomHelper.getDataObject(containerOid);
						
					byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
					
					//Make sure biometric data is present
					assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
					
					assertTrue(biometricData.length >= 40);
					
					
					byte[] biometricType = Arrays.copyOfRange(biometricData, 36, 39);
					
					assertNotNull(biometricType);
					
					assertTrue(biometricType.length >= 3);
					
					int type  = (((biometricType[0] & 0xFF) << 16) | ((biometricType[1] & 0xFF) << 8) | (biometricType[2] & 0xFF));
					//Check the value of Biometric Type
					assertTrue(type == value, "Biometrict data type was the wrong value, expected value " + value);
			    }
		    }
			if (!foundContainer) {
				String msg = "Invalid container specified in parameter for this test case";
				s_logger.error(msg);
			}
		}
		
		//Validate that that Biometric Type has the right value
		@DisplayName("SP800-76.42 test")
		@ParameterizedTest(name = "{index} => oid = {0}")
		//@MethodSource("sp800_76_BiometricParamTestProvider3")
		@ArgumentsSource(gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider.class)
		//@ArgumentsSource(ParameterizedArgumentsProvider.class)
		void sp800_76Test_42(String oid, String paramsString, TestReporter reporter) {
			Map<String, List<String>> mp = ParameterUtils.MapFromString(paramsString);
			assertNotNull(mp);
			Iterator<Map.Entry<String,List<String>>> it = mp.entrySet().iterator();
	        boolean foundContainer = false;
		    while (it.hasNext()) {
		    	Map.Entry<String,List<String>> pair = it.next();	    	
		        String containerName = pair.getKey();
		        if (containerName.compareTo(APDUConstants.containerOidToNameMap.get(oid)) == 0) {
		        	foundContainer = true;
			        List<String> valueStr =  pair.getValue();
					assertTrue(valueStr.size() == 1, "Illegal number of values for SP800-76.42 test: " + valueStr.size());
					String containerOid = APDUConstants.getStringForFieldNamed(containerName);
					assertNotNull(containerOid);
					boolean isMandatory = APDUConstants.isContainerMandatory(containerOid);
					// if the object is not mandatory and is not present, the test is done
					if(!isMandatory && !AtomHelper.isDataObjectPresent(containerOid, true)) {
						s_logger.info("Optional container {} ({}) is absent from the card.", containerName, containerOid);
						continue;
					} else {
						s_logger.info("Optional container {} ({}) is present on the card. Proceeding with test.", containerName, containerOid);
					}
	
					int value = 0;
					try {
						value = Integer.parseInt(valueStr.get(0));
					} catch(NumberFormatException e) {
						fail(e);
					}
	
					PIVDataObject o = AtomHelper.getDataObject(containerOid);
						
					byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
					
					//Make sure biometric data is present
					assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
					
					assertTrue(biometricData.length >= 41);
					
					//Check the value of Biometric Data Type			
					int type  = ((biometricData[39] & 0xFF));
					//Check the value of Biometric Type
					assertTrue(type == value, "Biometric data type was the wrong value, expected value " + value);
			    }
			}
			if (!foundContainer) {
				String msg = "Invalid container specified in parameter for this test case";
				s_logger.error(msg);
			}
		}
	
	//Validate that the biometric quality field carries valid values
	@DisplayName("SP800-76.43 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricParamTestProvider4")
	//@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_76Test_43(String oid, String param, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length >= 42);
		
		int quality = biometricData[40];
		
		String[] arrayParams = param.split(",");
		assertTrue(arrayParams.length == 2);
		
		int int1 = Integer.parseInt(arrayParams[0]);
		int int2 = Integer.parseInt(arrayParams[1]);
		
		//Confirm quality is set to a valid number.
		assertTrue(quality >= int1 && int2 <= 100, "Biometric quality has wrong values, expected values are " + int1 + " and " + int2);
	}
	
	//Validate that that the Creator field in the PIV Patron Format contains 18 bytes of which the first K <= 17 bytes shall be ASCII characters, and the first of the remaining 18-K shall be a null terminator (zero)
	@DisplayName("SP800-76.44 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_44(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length >= 61);
		
		byte[] creator = Arrays.copyOfRange(biometricData, 41, 59);
		
		//Confirm last byte is null
		assertTrue(Byte.compare(creator[creator.length-1], (byte)0x00) == 0);
		
		String s = new String(creator);
		
		//Check for ASCII
		assertTrue(s.matches("\\A\\p{ASCII}*\\z"), "Creator field is not ASCII");
	}
	
	//Validate that FASC-N field in the PIV Patron Format contains the same 25 bytes as the FASC-N component of the CHUID identifier
	@DisplayName("SP800-76.45 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_45(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
		PIVDataObject o2 = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length >= 85);
		
		byte[] fASCN = Arrays.copyOfRange(biometricData, 59, 84);
		
		byte[] fASCN2 = ((CardHolderUniqueIdentifier) o2).getfASCN();
		
		assertTrue(fASCN.length == fASCN2.length);
		
		//Confirm fascn match
		assertTrue(Arrays.equals(fASCN, fASCN2), "FASC-N value in biometric does not match FASC-N in CHUID");	
	}
	
	//Validate that the 'Reserved for Future Use' field is equal to 0x00000000
	@DisplayName("SP800-76.46 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_46(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData, "Biometric data is absent in CardHolderBiometricData object");
		
		assertTrue(biometricData.length >= 89);
		
		byte[] reserved = Arrays.copyOfRange(biometricData, 84, 88);
		
		byte[] zeros = { 0x00, 0x00, 0x00, 0x00};
		
		//Confirm Reserved field is all zeros
		assertTrue(Arrays.equals(reserved, zeros), "'Reserved for Future Use' field is not equal to 0x00000000");
		
	}

	//Confirm that Finger Quality value shall be 20, 40, 60, 80, 100, 254, or 255.
	@DisplayName("SP800-76.47 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void sp800_76Test_47(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricDataBlock = ((CardHolderBiometricData) o).getBiometricDataBlock();
		
		//Make sure biometric data block is present
		assertNotNull(biometricDataBlock, "Biometric data block is absent in CardHolderBiometricData object");
		        
		assertTrue(biometricDataBlock.length >= 27);
							
		byte [] numberOfFingerViewsBuff  = Arrays.copyOfRange(biometricDataBlock, 24, 25);
		assertNotNull(numberOfFingerViewsBuff);
				
		BigInteger numberOfFingersBI = new BigInteger(numberOfFingerViewsBuff);
        int numberOfFingers = numberOfFingersBI.intValue();
        
        List<Integer> qList = new ArrayList<Integer>();
        qList.add(20);
        qList.add(40);
        qList.add(60);
        qList.add(80);
        qList.add(100);
        qList.add(254);
        qList.add(255);
        
        int offset = 26;
        for (int view = 0; view < numberOfFingers; view++) {			

			Byte b1 = new Byte(biometricDataBlock[offset]);
			new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			b1.intValue();
			int fingerQuality = b3.intValue();
			b4.intValue();
			

	        assertTrue(qList.contains(fingerQuality), "Finger quality is not the right value " + fingerQuality + " Expected values are " + qList.toString());
        }
	}
		
	//Recorded SB length matches actual SB length
	@DisplayName("SP800-76.48 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_BiometricTestProvider")
	void sp800_76Test_48(String oid, TestReporter reporter) {
		boolean isMandatory = APDUConstants.isContainerMandatory(oid);
		// if the object is not mandatory and is not present, the test is done
		if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}
		PIVDataObject o = AtomHelper.getDataObject(oid);
			
		byte[] biometricData = ((CardHolderBiometricData) o).getBiometricData();
		byte[] signature = ((CardHolderBiometricData) o).getSignatureBlock();
				
		//Make sure signature is present
		assertNotNull(biometricData, "biometricData is absent in CardHolderBiometricData object");
		assertNotNull(biometricData, "Signature is absent in CardHolderBiometricData object");
		
		 if (biometricData != null && biometricData.length > 8) {

             //Get signature block (SB) Length
             byte[] signatureBlockLengthBytes = Arrays.copyOfRange(biometricData, 6, 8);
             
     		assertNotNull(signatureBlockLengthBytes, "Signature block length is absent in CardHolderBiometricData object");
     		
     		//Convert signature block (SB) Length byte[] value to int
            int signatureBlockLength = ((signatureBlockLengthBytes[0] & 0xff) << 8) | (signatureBlockLengthBytes[1] & 0xff);
            assertTrue(signatureBlockLength > 0);
            
            assertTrue(signature.length == signatureBlockLength,  "Biometric data block length does not match actual length");            
		 }
	}
	
	// methods below are no longer used in conformance test tool and are only retained because they are sometimes useful for
	// testing the atoms themselves
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_76_BiometricTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID),
						Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_76_FacialImageTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_76_FingerprintsTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}

	
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_76_BiometricParamTestProvider1() {

		String param = APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID + ":"+"1281"+","+APDUConstants.CARDHOLDER_FINGERPRINTS_OID+":"+"513";
			return Stream.of(Arguments.of(param));
	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_76_BiometricParamTestProvider2() {

		String param = APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID + ":"+"2"+","+APDUConstants.CARDHOLDER_FINGERPRINTS_OID+":"+"8";
			return Stream.of(Arguments.of(param));
	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_76_BiometricParamTestProvider3() {

		String param = APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID + ":"+"32"+","+APDUConstants.CARDHOLDER_FINGERPRINTS_OID+":"+"128";
			return Stream.of(Arguments.of(param));
	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_76_BiometricParamTestProvider4() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, "-2,100"),
						Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, "-2,100"));

	}
}
