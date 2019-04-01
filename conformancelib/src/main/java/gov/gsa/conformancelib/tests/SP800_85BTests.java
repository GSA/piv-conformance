package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
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
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_85BTests {

	//Validate that for mandatory fingerprint minutiae template data stored on a PIV card, the BDB Format Type is set to a value of 0x0201
	@DisplayName("SP800_85B.9.1.2.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FingerprintsTestProvider")
	void sp800_85B_Test_9_1_2_4(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 12);
		
		//Check format type field has a value of 0x0201
		assertTrue(Byte.compare(biometricData[10], (byte)0x02) == 0);
		assertTrue(Byte.compare(biometricData[11], (byte)0x01) == 0);
	}
	
	//Validate that that the creation date in the PIV Patron Format is encoded in 8 bytes using a binary representation of YYYYMMDDhhmmssZ
	@DisplayName("SP800_85B.9.1.2.5 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FingerprintsTestProvider")
	void sp800_85B_Test_9_1_2_5(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 21);
		
		
		byte[] biometricCreationDate = Arrays.copyOfRange(biometricData, 12, 12+8);
		
		assertNotNull(biometricCreationDate);
		
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
		String s = new String(biometricCreationDate);
        try {
			Date date = new SimpleDateFormat("YYYYMMDDhhmmssZ").parse(s);
			
			assertNotNull(date);
		} catch (ParseException e) {
			fail(e);
		}
	}
	
	//Validate date encoding on Validity Period in PIV Patron Format
	@DisplayName("SP800_85B.9.1.2.6 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FingerprintsTestProvider")
	void sp800_85B_Test_9_1_2_6(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 37);
		
		
		byte[] biometricValidityPeriodDate1 = Arrays.copyOfRange(biometricData, 20, 8);
		byte[] biometricValidityPeriodDate2 = Arrays.copyOfRange(biometricData, 28, 36);
		
		assertNotNull(biometricValidityPeriodDate1);
		assertNotNull(biometricValidityPeriodDate2);
		
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
		String s = new String(biometricValidityPeriodDate1);
        try {
			Date date = new SimpleDateFormat("YYYYMMDDhhmmssZ").parse(s);
			
			assertNotNull(date);
		} catch (ParseException e) {
			fail(e);
		}
        
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
		s = new String(biometricValidityPeriodDate2);
        try {
			Date date = new SimpleDateFormat("YYYYMMDDhhmmssZ").parse(s);
			
			assertNotNull(date);
		} catch (ParseException e) {
			fail(e);
		}
	}
	
	//Validate that that Biometric Type has the value 0x000008
	@DisplayName("SP800_85B.9.1.2.7 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FingerprintsTestProvider")
	void sp800_85B_Test_9_1_2_7(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 40);
		
		
		byte[] biometricType = Arrays.copyOfRange(biometricData, 36, 39);
		
		assertNotNull(biometricType);
		
		assertTrue(biometricType.length >= 3);
		
		//Check the value of Biometric Type
		assertTrue(Byte.compare(biometricType[0], (byte)0x00) == 0);
		assertTrue(Byte.compare(biometricType[1], (byte)0x00) == 0);
		assertTrue(Byte.compare(biometricType[2], (byte)0x08) == 0);
	}
	
	//Validate that for the mandatory minutia PIV card templates, the CBEFF biometric data type encoding value shall be b100xxxxx, which corresponds to biometric data that has been processed.
	@DisplayName("SP800_85B.9.1.2.8 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FingerprintsTestProvider")
	void sp800_85B_Test_9_1_2_8(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 41);
		
		//Check the value of Biometric Data Type
		assertTrue(Byte.compare(biometricData[40], (byte)0x80) == 0);
	}
	
	//Validate that the biometric quality field carries valid values
	@DisplayName("SP800_85B.9.1.2.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_BiometricTestProvider")
	void sp800_85B_Test_9_1_2_9(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 42);
		
		int quality = biometricData[41];
		
		//Confirm quality is set to a valid number.
		assertTrue(quality == -2 || quality == -1 || (quality >= 0 && quality <= 100));
	}
	
	//Validate that that the Creator field in the PIV Patron Format contains 18 bytes of which the first K <= 17 bytes shall be ASCII characters, and the first of the remaining 18-K shall be a null terminator (zero)
	@DisplayName("SP800_85B.9.1.2.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_BiometricTestProvider")
	void sp800_85B_Test_9_1_2_10(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 61);
		
		byte[] creator = Arrays.copyOfRange(biometricData, 42, 60);
		
		//Confirm last byte is null
		assertTrue(Byte.compare(creator[creator.length-1], (byte)0x00) == 0);
		
		String s = new String(creator);
		
		for (int i = 0; i < s.length()-1; i++){
		    char c = s.charAt(i);        
		    assertTrue(c >= 32 && c < 127);
		}
	}
	
	//Validate that FASC-N field in the PIV Patron Format contains the same 25 bytes as the FASC-N component of the CHUID identifier
	@DisplayName("SP800_85B.9.1.2.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_BiometricTestProvider")
	void sp800_85B_Test_9_1_2_11(String oid, TestReporter reporter) {
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
        PIVDataObject o2 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		assertNotNull(o);
		assertNotNull(o2);

		// Get data from the card corresponding to the OID value
		MiddlewareStatus result = piv.pivGetData(ch, oid, o);
		assertTrue(result == MiddlewareStatus.PIV_OK);
		

		result = piv.pivGetData(ch, APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, o2);
		assertTrue(result == MiddlewareStatus.PIV_OK);

	    boolean decoded = o.decode();
		assertTrue(decoded);
		
		decoded = o2.decode();
		assertTrue(decoded);
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		assertTrue(biometricData.length >= 87);
		
		byte[] fASCN = Arrays.copyOfRange(biometricData, 61, 86);
		
		byte[] fASCN2 = ((CardHolderUniqueIdentifier) o2).getfASCN();
		
		assertTrue(fASCN.length == fASCN2.length);
		
		//Confirm fascn match
		assertTrue(Arrays.equals(fASCN, fASCN2));
		
	}
	
	//Validate that the 'Reserved for Future Use' field is equal to 0x00000000
	@DisplayName("SP800_85B.9.1.2.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_BiometricTestProvider")
	void sp800_85B_Test_9_1_2_12(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 92);
		
		byte[] reserved = Arrays.copyOfRange(biometricData, 87, 91);
		
		byte[] zeros = { 0x00, 0x00, 0x00, 0x00};
		
		//Confirm Reserved field is all zeros
		assertTrue(Arrays.equals(reserved, zeros));
		
	}
	
	//Validate that for optional facial image data stored on a PIV card, the BDB Format Type is set to a value of 0x0501
	@DisplayName("SP800_85B.9.2.2.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_4(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 12);
		
		//Check the 8th and 9th bytes of biometric data to confirm BDB Format Owner field has a value of 0x0501
		assertTrue(Byte.compare(biometricData[10], (byte)0x05) == 0);
		assertTrue(Byte.compare(biometricData[11], (byte)0x01) == 0);
	}
	
	//Validate that that the creation date in the PIV Patron Format is encoded in 8 bytes using a binary representation of 'YYYYMMDDhhmmssZ'
	@DisplayName("SP800_85B.9.2.2.5 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_5(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 21);
		
		
		byte[] biometricCreationDate = Arrays.copyOfRange(biometricData, 12, 12+8);
		
		assertNotNull(biometricCreationDate);
		
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
		String s = new String(biometricCreationDate);
        try {
			Date date = new SimpleDateFormat("YYYYMMDDhhmmssZ").parse(s);
			
			assertNotNull(date);
		} catch (ParseException e) {
			fail(e);
		}
	}
	
	//Validate date encoding on Validity Period in PIV Patron Format
	@DisplayName("SP800_85B.9.1.2.6 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_6(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 37);
		
		
		byte[] biometricValidityPeriodDate1 = Arrays.copyOfRange(biometricData, 20, 8);
		byte[] biometricValidityPeriodDate2 = Arrays.copyOfRange(biometricData, 28, 36);
		
		assertNotNull(biometricValidityPeriodDate1);
		assertNotNull(biometricValidityPeriodDate2);
		
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
		String s = new String(biometricValidityPeriodDate1);
        try {
			Date date = new SimpleDateFormat("YYYYMMDDhhmmssZ").parse(s);
			
			assertNotNull(date);
		} catch (ParseException e) {
			fail(e);
		}
        
		//Get the creation date value and parse it into a Data object using "YYYYMMDDhhmmssZ" format
		s = new String(biometricValidityPeriodDate2);
        try {
			Date date = new SimpleDateFormat("YYYYMMDDhhmmssZ").parse(s);
			
			assertNotNull(date);
		} catch (ParseException e) {
			fail(e);
		}
	}
	
	//Validate that that Biometric Type has the value 0x000002
	@DisplayName("SP800_85B.9.2.2.7 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_7(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 40);
		
		
		byte[] biometricType = Arrays.copyOfRange(biometricData, 36, 39);
		
		assertNotNull(biometricType);
		
		assertTrue(biometricType.length >= 3);
		
		//Check the value of Biometric Type
		assertTrue(Byte.compare(biometricType[0], (byte)0x00) == 0);
		assertTrue(Byte.compare(biometricType[1], (byte)0x00) == 0);
		assertTrue(Byte.compare(biometricType[2], (byte)0x02) == 0);
	}
	
	//Validate that the CBEFF biometric data type encoding value shall be b001xxxxx, which corresponds to the raw biometric data
	@DisplayName("SP800_85B.9.2.2.8 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_8(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 41);
		
		//Check the value of Biometric Data Type
		assertTrue(Byte.compare(biometricData[40], (byte)0x20) == 0);
	}
	
	//Validate that the biometric quality field carries valid values
	@DisplayName("SP800_85B.9.2.2.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_9(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 42);
		
		int quality = biometricData[41];
		
		//Confirm quality is set to a valid number.
		assertTrue(quality == -2 || quality == -1 || (quality >= 0 && quality <= 100));
	}
	
	
	//Validate that that the Creator field in the PIV Patron Format contains 18 bytes of which the first K <= 17 bytes shall be ASCII characters, and the first of the remaining 18-K shall be a null terminator (zero)
	@DisplayName("SP800_85B.9.2.2.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_10(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 61);
		
		byte[] creator = Arrays.copyOfRange(biometricData, 42, 60);
		
		//Confirm last byte is null
		assertTrue(Byte.compare(creator[creator.length-1], (byte)0x00) == 0);
		
		String s = new String(creator);
		
		for (int i = 0; i < s.length()-1; i++){
		    char c = s.charAt(i);        
		    assertTrue(c >= 32 && c < 127);
		}
	}
	
	//Validate that FASC-N field in the PIV Patron Format contains the same 25 bytes as the FASC-N component of the CHUID identifier
	@DisplayName("SP800_85B.9.2.2.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_11(String oid, TestReporter reporter) {
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
        PIVDataObject o2 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		assertNotNull(o);
		assertNotNull(o2);

		// Get data from the card corresponding to the OID value
		MiddlewareStatus result = piv.pivGetData(ch, oid, o);
		assertTrue(result == MiddlewareStatus.PIV_OK);
		

		result = piv.pivGetData(ch, APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, o2);
		assertTrue(result == MiddlewareStatus.PIV_OK);

	    boolean decoded = o.decode();
		assertTrue(decoded);
		
		decoded = o2.decode();
		assertTrue(decoded);
			
		byte[] biometricData = ((CardholderBiometricData) o).getBiometricData();
		
		//Make sure biometric data is present
		assertNotNull(biometricData);
		
		assertTrue(biometricData.length >= 87);
		
		byte[] fASCN = Arrays.copyOfRange(biometricData, 61, 86);
		
		byte[] fASCN2 = ((CardHolderUniqueIdentifier) o2).getfASCN();
		
		assertTrue(fASCN.length == fASCN2.length);
		
		//Confirm fascn match
		assertTrue(Arrays.equals(fASCN, fASCN2));
		
	}
	
	//Validate that the 'Reserved for Future Use' field is equal to 0x00000000
	@DisplayName("SP800_85B.9.1.2.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_85B_FacialImageTestProvider")
	void sp800_85B_Test_9_2_2_12(String oid, TestReporter reporter) {
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
		
		assertTrue(biometricData.length >= 92);
		
		byte[] reserved = Arrays.copyOfRange(biometricData, 87, 91);
		
		byte[] zeros = { 0x00, 0x00, 0x00, 0x00};
		
		//Confirm Reserved field is all zeros
		assertTrue(Arrays.equals(reserved, zeros));
		
	}
	
	private static Stream<Arguments> sp800_85B_FingerprintsTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}
	
	private static Stream<Arguments> sp800_85B_FacialImageTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID));
	}
	
	private static Stream<Arguments> sp800_85B_BiometricTestProvider() {

		return Stream.of(
                Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID),
                Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID));

	}

}
