package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;
import java.util.Iterator;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Store;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
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
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.CardholderBiometricData;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;

public class Armen_PlaceholderTests {

	
	//check expiration date of content signing cert.
	@DisplayName("Issue.65 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_73_4_CHUIDTestProvider")
    void Issue_65(String oid, TestReporter reporter) {
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
		
		
		X509Certificate cert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		Calendar cal = Calendar.getInstance();
		Date today = cal.getTime();
		
		assertTrue(cert.getNotAfter().compareTo(today) >= 0);
       
    }
	
	//Confirm that Finger Quality value shall be 20, 40, 60, 80, 100, 254, or 255.
	@DisplayName("Issue.62 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("sp800_76_FingerprintsTestProvider")
	void Issue_62(String oid, TestReporter reporter) {
		assertNotNull(oid);
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		assertNotNull(css);
		if (css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_FAIL) {
			ConformanceTestException e = new ConformanceTestException(
					"Login has already been attempted and failed. Not trying again.");
			fail(e);
		}
		try {
			css.setApplicationPin("123456");
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
			Byte b2 = new Byte(biometricDataBlock[offset+1]);
			Byte b3 = new Byte(biometricDataBlock[offset+2]);
			Byte b4 = new Byte(biometricDataBlock[offset+3]);
			int fingerPosition = b1.intValue();
			int viewNumber = ((biometricDataBlock[offset+1] & 0xF0) >> 4);
			int impressionType = ((biometricDataBlock[offset+1] & 0x0F) << 8);
			int fingerQuality = b3.intValue();
			int numberOfMinutiae = b4.intValue();
			

	        assertTrue(qList.contains(fingerQuality));
        }
	}
        
	private static Stream<Arguments> sp800_76_FingerprintsTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}
	
	private static Stream<Arguments> sp800_73_4_CHUIDTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}
	
	private static Stream<Arguments> pKIX_x509TestProvider2() {

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
		PIVDataObject o1 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
		PIVDataObject o2 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
		PIVDataObject o3 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
		PIVDataObject o4 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
		PIVDataObject o5 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		assertNotNull(o1);
		assertNotNull(o2);
		assertNotNull(o3);
		assertNotNull(o4);
		assertNotNull(o5);
		
		AbstractPIVApplication piv = css.getPivHandle();
		CardHandle c = css.getCardHandle();
		MiddlewareStatus result = MiddlewareStatus.PIV_OK;
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, o1);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o1.decode() == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, o2);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o2.decode() == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, o3);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o3.decode() == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, o4);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o4.decode() == true);
			
		result = piv.pivGetData(c, APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, o5);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o5.decode() == true);

		X509Certificate cert1 = ((X509CertificateDataObject) o1).getCertificate();
		assertNotNull(cert1);
		
		X509Certificate cert2 = ((X509CertificateDataObject) o2).getCertificate();
		assertNotNull(cert2);
		
		X509Certificate cert3 = ((X509CertificateDataObject) o3).getCertificate();
		assertNotNull(cert3);
		
		X509Certificate cert4 = ((X509CertificateDataObject) o4).getCertificate();
		assertNotNull(cert4);
		
		X509Certificate cert5 = ((CardHolderUniqueIdentifier) o5).getSigningCertificate();
		assertNotNull(cert5);

		return Stream.of(Arguments.of(cert1, "2.5.29.31"),Arguments.of(cert2, "2.5.29.31"),Arguments.of(cert3, "2.5.29.31"),
				Arguments.of(cert4, "2.5.29.31"),Arguments.of(cert5, "2.5.29.31"));

	}
	
}
