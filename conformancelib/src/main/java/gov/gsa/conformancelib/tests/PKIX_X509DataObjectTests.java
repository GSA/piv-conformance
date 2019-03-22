package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
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
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class PKIX_X509DataObjectTests {

	// Verify signature algorithm conforms to 78.1, 78.2, 78.3
	@DisplayName("PKIX.1 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("pKIX_x509TestProvider")
	void PKIX_Test_1(String oid, TestReporter reporter) {
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
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
		assertNotNull(o);
		AbstractPIVApplication piv = css.getPivHandle();
		CardHandle c = css.getCardHandle();
		MiddlewareStatus result = MiddlewareStatus.PIV_OK;
		result = piv.pivGetData(c, oid, o);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o.decode());

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();

		if (pubKey instanceof RSAPublicKey) {
			assertTrue(pubKey.getModulus().bitLength() == 2048);
		}

		if (pubKey instanceof ECPublicKey) {

			ECPublicKey pk = (ECPublicKey) pubKey;
			ECParameterSpec params = pk.getParams();

			EllipticCurve ec = params.getCurve();

			// XXX Not sure how to get curve name from here
		}

		List<String> algList = new ArrayList<String>();

		algList.add("1.2.840.113549.1.1.5");
		algList.add("1.2.840.113549.1.1.10");
		algList.add("1.2.840.113549.1.1.11");
		algList.add("1.2.840.10045.4.3.2");
		algList.add("1.2.840.10045.4.3.3");

		String sigAlgFromCert = cert.getSigAlgOID();

		assertTrue(algList.contains(sigAlgFromCert));
	}

	// Confirm keyUsage extension is present
	@DisplayName("PKIX.2 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("pKIX_x509TestProvider")
	void PKIX_Test_2(String oid, TestReporter reporter) {
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
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
		assertNotNull(o);
		AbstractPIVApplication piv = css.getPivHandle();
		CardHandle c = css.getCardHandle();
		MiddlewareStatus result = MiddlewareStatus.PIV_OK;
		result = piv.pivGetData(c, oid, o);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o.decode());

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		assertTrue(cert.getKeyUsage() != null);
	}

	// Confirm digitalSignature bit is set
	@DisplayName("PKIX.3 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("pKIX_PIVAuthx509TestProvider")
	void PKIX_Test_3(String oid, TestReporter reporter) {
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
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
		assertNotNull(o);
		AbstractPIVApplication piv = css.getPivHandle();
		CardHandle c = css.getCardHandle();
		MiddlewareStatus result = MiddlewareStatus.PIV_OK;
		result = piv.pivGetData(c, oid, o);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o.decode());

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// taken out and placed somewhere else?
		// Confirm digitalSignature bit is set
		assertTrue(ku[0] == true);

	}

	// Confirm no other bits are set
	@DisplayName("PKIX.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("pKIX_PIVAuthx509TestProvider")
	void PKIX_Test_4(String oid, TestReporter reporter) {
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
		PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
		assertNotNull(o);
		AbstractPIVApplication piv = css.getPivHandle();
		CardHandle c = css.getCardHandle();
		MiddlewareStatus result = MiddlewareStatus.PIV_OK;
		result = piv.pivGetData(c, oid, o);
		assert (result == MiddlewareStatus.PIV_OK);
		assert (o.decode());

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// XXX this would only be valid for signature certs does this test need to be
		// taken out and placed somewhere else?
		// Confirm digitalSignature bit is set
		assertTrue(ku[0] == true);
		assertTrue(ku[1] == false);
		assertTrue(ku[2] == false);
		assertTrue(ku[3] == false);
		assertTrue(ku[4] == false);
		assertTrue(ku[5] == false);
		assertTrue(ku[6] == false);
		assertTrue(ku[7] == false);

	}

	// Confirm certificate policies extension is present
	@DisplayName("PKIX.5 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_5(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null);
		
    }
	
	// Confirm that id- fpki-common-authentication 2.16.840.1.101.3.2.1.3.13 OID is asserted in certificate policies
	@DisplayName("PKIX.6 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_6(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null);
		
		CertificatePolicies policies = CertificatePolicies.getInstance(cpex);
		
		boolean containsOOID = false;
		
	    PolicyInformation[] policyInformation = policies.getPolicyInformation();
	    for (PolicyInformation pInfo : policyInformation) {
	    	ASN1ObjectIdentifier curroid = pInfo.getPolicyIdentifier();
	    	if(curroid.getId().compareTo("2.16.840.1.101.3.2.1.3.13") == 0) {
	    		containsOOID = true;
	    	}
	    }
	    
	    //Confirm that id- fpki-common-authentication 2.16.840.1.101.3.2.1.3.13 OID is asserted in certificate policies
	    assertTrue(containsOOID);
		
    }
	
	//Confirm that authorityInformationAccess extension is present
	@DisplayName("PKIX.7 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_7(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
		
		
    }
	
	//Confirm that an access method containing id-ad-ocsp is present
	@DisplayName("PKIX.8 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_8(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
		
		AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaex);
		
		assertTrue(aia != null);
		
		boolean ocsppresent = false;
		AccessDescription[] ads = aia.getAccessDescriptions();
        for (int i = 0; i < ads.length; i++)
        {
            if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp))
            {
            	ocsppresent = true;
            }
        }
        
        //Confirm access method containing id-ad-ocsp is present
        assertTrue(ocsppresent);
    }
	
	//Confirm that the access method is uniformResourceIdentifier and that protocol is http
	@DisplayName("PKIX.9 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_9(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
		
		AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(aiaex);
		
		assertTrue(aia != null);
		
		boolean ocsppresent = false;
		AccessDescription[] ads = aia.getAccessDescriptions();
        for (int i = 0; i < ads.length; i++)
        {
            if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp))
            {
            	ocsppresent = true;
            }
        }
        
        //Confirm access method containing id-ad-ocsp is present
        assertTrue(ocsppresent);
    }
	
	//Confirm that piv interim extension is present
	@DisplayName("PKIX.10 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_10(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//XXX Placeholder as I don't know what piv interim extension is
		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
		
    }
	
	//Sign arbitrary data using the specified key container and confirm that the certificate can validate it
	@DisplayName("PKIX.11 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_11(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//XXX Placeholder Not sure how to do this test yet

		
    }
	
	//Confirm that the certificate subjectAltName includes FASC-N and that it matches CHUID
	@DisplayName("PKIX.12 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_12(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();


		//XXX Placeholder need to figure out a way to get the CHUID
		try {
			Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
	        if (altNames != null) {
	            for (List<?> altName : altNames) {
	                Integer altNameType = (Integer) altName.get(0);
	                if (altNameType != 2 && altNameType != 7) // dns or ip
	                    continue;
	            }
	        }
		} catch (CertificateParsingException e) {
			fail(e);
		}

		
    }
	
	//Confirm that expiration of certificate is not later than expiration of card
	@DisplayName("PKIX.13 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_13(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		//XXX Placeholder need to figure out a way to cart expiration date
		Date notAfter =  cert.getNotAfter();
		assertNotNull(notAfter);
    }

	//For RSA certs, confirm that public exponent >= 65537
	@DisplayName("PKIX.14 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_14(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
		
		
		BigInteger be = BigInteger.valueOf(65537);
		
		if(pubKey instanceof RSAPublicKey) {
			//confirm that public exponent >= 65537
			assertTrue(pubKey.getPublicExponent().compareTo(be) >= 0);
		} 
    }
	
	//Confirm digitalSignature and nonRepudiation bits are set
	@DisplayName("PKIX.15 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_DigSigx509TestProvider")
    void PKIX_Test_15(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// taken out and placed somewhere else?
		// Confirm digitalSignature and nonRepudiation bit is set
		assertTrue(ku[0] == true);
		assertTrue(ku[1] == true);
    }
	
	
	//Confirm Key Management certificates for RSA keys have keyEncipherment bit set
	@DisplayName("PKIX.16 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_KeyMgmtx509TestProvider")
    void PKIX_Test_16(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// taken out and placed somewhere else?
		// Confirm keyEncipherment bit is set
		assertTrue(ku[2] == true);
    }
	
	//Confirm Key Management certificates for elliptic curve keys have keyAgreement bit set 
	@DisplayName("PKIX.17 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_KeyMgmtx509TestProvider")
    void PKIX_Test_17(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		
		PublicKey pubKey = (ECPublicKey) cert.getPublicKey();

		if(pubKey instanceof ECPublicKey) {
		
			boolean[] ku = cert.getKeyUsage();

			// confirm key usage extension is present
			assertTrue(ku != null);

			// taken out and placed somewhere else?
			// Confirm keyAgreement bit is set
			assertTrue(ku[4] == true);
		}
		
    }
	
	//Confirm that id- fpki-common-cardAuth 2.16.840.1.101.3.2.1.3.17 OID is asserted in certificate policies
	@DisplayName("PKIX.18 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_CardAuthx509TestProvider")
    void PKIX_Test_18(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		
		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null);
		
		CertificatePolicies policies = CertificatePolicies.getInstance(cpex);
		
		boolean containsOOID = false;
		
	    PolicyInformation[] policyInformation = policies.getPolicyInformation();
	    for (PolicyInformation pInfo : policyInformation) {
	    	ASN1ObjectIdentifier curroid = pInfo.getPolicyIdentifier();
	    	if(curroid.getId().compareTo("2.16.840.1.101.3.2.1.3.17") == 0) {
	    		containsOOID = true;
	    	}
	    }
	    
	    //Confirm that id- fpki-common-cardAuth  2.16.840.1.101.3.2.1.3.17 OID is asserted in certificate policies
	    assertTrue(containsOOID);
		
    }
	
	//Confirm extendedKeyUsage extension is present
	@DisplayName("PKIX.19 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_CardAuthx509TestProvider")
    void PKIX_Test_19(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		
		//Get eku extension
		byte[] cpex = cert.getExtensionValue("2.5.29.37");
		
		//Confirm eku extension is present
		assertTrue(cpex != null);
    }

	//Confirm id-PIV-cardAuth 2.16.840.1.101.3.2.1.3.17 exists in extendedKeyUsage extension
	@DisplayName("PKIX.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_CardAuthx509TestProvider")
    void PKIX_Test_20(String oid, TestReporter reporter) {
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
        PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(oid);
        assertNotNull(o);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        result = piv.pivGetData(c, oid, o);
        assert(result == MiddlewareStatus.PIV_OK);
        assert(o.decode());
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		
		//Get certificate policies extension
		byte[] ekuex = cert.getExtensionValue("2.5.29.37");
		
		//Confirm certificate policies extension is present
		assertTrue(ekuex != null);
		
		ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ekuex);
		
		boolean containsOOID = false;
		
	    KeyPurposeId[] kpilist = eku.getUsages();
	    for (KeyPurposeId kpiInfo : kpilist) {
	    	if(kpiInfo.getId().compareTo("2.16.840.1.101.3.2.1.3.17") == 0) {
	    		containsOOID = true;
	    	}
	    }
	    
	    //Confirm that id- fpki-common-cardAuth  2.16.840.1.101.3.2.1.3.17 OID is present in eku
	    assertTrue(containsOOID);
		
    }
	
	private static Stream<Arguments> pKIX_x509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID));

	}
	
	private static Stream<Arguments> pKIX_PIVAuthx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID));

	}
	
	private static Stream<Arguments> pKIX_DigSigx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID));

	}
	
	private static Stream<Arguments> pKIX_KeyMgmtx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID));

	}
	
	private static Stream<Arguments> pKIX_CardAuthx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID));

	}
}
