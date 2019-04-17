package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

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
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;

public class PKIX_X509DataObjectTests {

	// Verify signature algorithm conforms to 78.1, 78.2, 78.3
	@DisplayName("PKIX.1 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("pKIX_x509TestProvider")
	void PKIX_Test_1(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);

		PublicKey pubKey = cert.getPublicKey();

		if (pubKey instanceof RSAPublicKey) {
			RSAPublicKey pk = (RSAPublicKey) pubKey;
			assertTrue(pk.getModulus().bitLength() == 2048);
		}

		if (pubKey instanceof ECPublicKey) {

			String supportedCurve = "prime256v1";
			
			ECPublicKey pk = (ECPublicKey) pubKey;
	        ECParameterSpec ecParameterSpec = pk.getParameters();
	        
	        String curveFromCert = "";
	        for (Enumeration<?> names = ECNamedCurveTable.getNames(); names.hasMoreElements();) {
	        	
		        String name = (String)names.nextElement();
	
		        X9ECParameters params = ECNamedCurveTable.getByName(name);
	
		        if (params.getN().equals(ecParameterSpec.getN())
		            && params.getH().equals(ecParameterSpec.getH())
		            && params.getCurve().equals(ecParameterSpec.getCurve())
		            && params.getG().equals(ecParameterSpec.getG())){
		        	curveFromCert = name;
		        }
	        }
	        
	        //Confirm that the curve in the cert is prime256v1
	        assertTrue(supportedCurve.compareTo(curveFromCert) == 0);
		}

		List<String> algList = new ArrayList<String>();

		algList.add("1.2.840.113549.1.1.5");
		algList.add("1.2.840.113549.1.1.10");
		algList.add("1.2.840.113549.1.1.11");
		algList.add("1.2.840.10045.4.3.2");
		algList.add("1.2.840.10045.4.3.3");

		String sigAlgFromCert = cert.getSigAlgOID();

		boolean present = false;
		for (int i = 0; i < algList.size(); i++) {
			
			if(algList.get(i).compareTo(sigAlgFromCert) == 0) {
				present = true;
				break;
			}
		}
		assertTrue(present);
		
	}

	// Confirm keyUsage extension is present
	@DisplayName("PKIX.2 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@MethodSource("pKIX_x509TestProvider")
	void PKIX_Test_2(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);

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
		boolean decoded = o.decode();
		assert (decoded == true);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);

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
		boolean decoded = o.decode();
		assert (decoded == true);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);
		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

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
    void PKIX_Test_5(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);

		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null);
		
    }
	
	// Confirm that id- fpki-common-authentication 2.16.840.1.101.3.2.1.3.13 OID is asserted in certificate policies
	@DisplayName("PKIX.6 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_PIVAuthx509TestProvide2")
    void PKIX_Test_6(String oid, String policyOid, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(policyOid);
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
        boolean decoded = o.decode();
        assert(decoded == true);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);

		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null);
		
		CertificatePolicies policies = null;
		try {
			policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(cpex));
		} catch (IOException e) {
			fail(e);
		}
		assertNotNull(policies);
		boolean containsOOID = false;
		
	    PolicyInformation[] policyInformation = policies.getPolicyInformation();
	    for (PolicyInformation pInfo : policyInformation) {
	    	ASN1ObjectIdentifier curroid = pInfo.getPolicyIdentifier();
	    	if(curroid.getId().compareTo(policyOid) == 0) {
	    		containsOOID = true;
	    		break;
	    	}
	    }
	    
	    //Confirm that oid matches is asserted in certificate policies
	    assertTrue(containsOOID);
		
    }
	
	//Confirm that authorityInformationAccess extension is present
	@DisplayName("PKIX.7 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_7(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
	}
	
	//Confirm that an access method containing id-ad-ocsp is present
	@DisplayName("PKIX.8 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_8(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
		
		AuthorityInformationAccess aia = null;
		try {
			aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(aiaex));
		} catch (IOException e) {
			fail(e);
		}
		
		assertNotNull(aia);
		
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
    void PKIX_Test_9(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
		
		AuthorityInformationAccess aia = null;
		try {
			aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(aiaex));
		} catch (IOException e) {
			fail(e);
		}
		
		assertNotNull(aia);
		
		boolean ocsppresent = false;
		AccessDescription[] ads = aia.getAccessDescriptions();
        for (int i = 0; i < ads.length; i++)
        {
            if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp))
            {
            	GeneralName gn = ads[i].getAccessLocation();
            	
            	assertTrue (gn.getTagNo() == GeneralName.uniformResourceIdentifier);
                String url = ((DERIA5String) gn.getName()).getString();

                assertTrue(url.startsWith("http"));
            	ocsppresent = true;
            }
        }
        
        //Confirm access method containing id-ad-ocsp is present
        assertTrue(ocsppresent);
    }
	
	//Confirm that piv interim "2.16.840.1.101.3.6.9.1" extension is present
	@DisplayName("PKIX.10 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_PIVAuthx509TestProvider")
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
			
			//CardUtils.authenticateInSingleton(false);
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
        
        boolean decoded = o.decode();
        assertTrue(decoded);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		assertNotNull(cert);
		//Get piv interim "2.16.840.1.101.3.6.9.1" extension
		byte[] aiaex = cert.getExtensionValue("2.16.840.1.101.3.6.9.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null);
		assertTrue(aiaex.length > 0);
		
    }
	
	//Sign arbitrary data using the specified key container and confirm that the certificate can validate it
	@DisplayName("PKIX.11 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_11(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);
		// XXX *** shelve to do merge
    }
	
	//Confirm that the certificate subjectAltName includes FASC-N and that it matches CHUID
	@DisplayName("PKIX.12 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider2")
    void PKIX_Test_12(X509Certificate cert, String oid, TestReporter reporter) {
		assertNotNull(cert);
		assertNotNull(oid);
		
		//XXX Not sure what to do with the second parameter
		
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
        PIVDataObject o2 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        assertNotNull(o2);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
        

        result = piv.pivGetData(c, APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, o2);
        assert(result == MiddlewareStatus.PIV_OK);
        boolean decoded = o2.decode();
        assert(decoded == true);
               
		byte[] fascn = ((CardHolderUniqueIdentifier) o2).getfASCN();
		System.out.println(new String(fascn));
		
		try {
			Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
	        if (altNames != null) {
	            for (List<?> altName : altNames) {
	                Integer altNameType = (Integer) altName.get(0);
	                if (altNameType == 0) {
	                	byte[] otherName = (byte[]) altName.toArray()[1];
               	
	                	byte[] fascnFromCert = Arrays.copyOfRange(otherName, 18, otherName.length);
	                	assertTrue(Arrays.equals(fascnFromCert, fascn));
	                }
	            }
	        }
		} catch (CertificateParsingException e) {
			fail(e);
		}
    }
	
	//Confirm that expiration of certificate is not later than expiration of card
	@DisplayName("PKIX.13 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider3")
    void PKIX_Test_13(X509Certificate cert, int years, TestReporter reporter) {
		assertNotNull(cert);
		assertNotNull(years);
		
		//XXX Not sure what to do with years value

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
        PIVDataObject o2 = PIVDataObjectFactory.createDataObjectForOid(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        AbstractPIVApplication piv = css.getPivHandle();
        CardHandle c = css.getCardHandle();
        MiddlewareStatus result = MiddlewareStatus.PIV_OK;
       
        result = piv.pivGetData(c, APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, o2);
        assert(result == MiddlewareStatus.PIV_OK);
        boolean decoded = o2.decode();
        assert(decoded == true);

        
		Date notAfter =  cert.getNotAfter();
		assertNotNull(notAfter);
		
		Date expirationDate = ((CardHolderUniqueIdentifier) o2).getExpirationDate();
				
		//Confirm that expiration of certificate is not later than expiration of card
		assertTrue(notAfter.compareTo(expirationDate) <= 0);
    }

	//For RSA certs, confirm that public exponent >= 65537
	@DisplayName("PKIX.14 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_14(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);

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
        boolean decoded = o.decode();
        assert(decoded == true);
       
        X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);

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
        boolean decoded = o.decode();
        assert(decoded == true);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);

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
        boolean decoded = o.decode();
        assert(decoded == true);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);
		
		PublicKey pubKey = cert.getPublicKey();

		if(pubKey instanceof ECPublicKey) {
		
			boolean[] ku = cert.getKeyUsage();

			// confirm key usage extension is present
			assertTrue(ku != null);
			// Confirm keyAgreement bit is set
			assertTrue(ku[4] == true);
		}
		
    }
	
	//Confirm that id- fpki-common-cardAuth 2.16.840.1.101.3.2.1.3.17 OID is asserted in certificate policies
	@DisplayName("PKIX.18 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_CardAuthx509TestProvider2")
    void PKIX_Test_18(String oid, String policyOid, TestReporter reporter) {
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
        boolean decoded = o.decode();
        assert(decoded == true);
       
        X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);
		
		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null);
		
		CertificatePolicies policies = null;
		try {
			policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(cpex));
		} catch (IOException e) {
			fail(e);
		}
		
		boolean containsOOID = false;
		
	    PolicyInformation[] policyInformation = policies.getPolicyInformation();
	    for (PolicyInformation pInfo : policyInformation) {
	    	ASN1ObjectIdentifier curroid = pInfo.getPolicyIdentifier();
	    	if(curroid.getId().compareTo(policyOid) == 0) {
	    		containsOOID = true;
	    	}
	    }
	    
	    //Confirm that policy oid is present
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
        boolean decoded = o.decode();
        assert(decoded == true);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);
		
		//Get eku extension
		byte[] cpex = cert.getExtensionValue("2.5.29.37");
		
		//Confirm eku extension is present
		assertTrue(cpex != null);
    }

	//Confirm id-PIV-cardAuth 2.16.840.1.101.3.6.8 exists in extendedKeyUsage extension
	@DisplayName("PKIX.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_CardAuthx509TestProvider2")
    void PKIX_Test_20(String oid, String ekuOid, TestReporter reporter) {
        assertNotNull(oid);
        assertNotNull(ekuOid);
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
        boolean decoded = o.decode();
        assert(decoded == true);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);
		
		//Get certificate policies extension
		byte[] ekuex = cert.getExtensionValue("2.5.29.37");
		
		//Confirm certificate policies extension is present
		assertTrue(ekuex != null);
		
		ExtendedKeyUsage eku = null;
		try {
			eku = ExtendedKeyUsage.getInstance(X509ExtensionUtil.fromExtensionValue(ekuex));
		} catch (IOException e) {
			fail(e);
		}
		
		assertNotNull(eku);
		boolean containsOOID = false;
		
	    KeyPurposeId[] kpilist = eku.getUsages();
	    for (KeyPurposeId kpiInfo : kpilist) {
	    	if(kpiInfo.getId().compareTo(ekuOid) == 0) {
	    		containsOOID = true;
	    	}
	    }
	    
	    //Confirm that id-PIV-cardAuth 2.16.840.1.101.3.6.8 OID is present in eku
	    assertTrue(containsOOID);
		
    }

	// placeholder
	@DisplayName("PKIX.21 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_CardAuthx509TestProvider2")
    void PKIX_Test_21(String oid, String ekuOid, TestReporter reporter) {
		assert(false);
	}

	//The authorityInfoAccess field contains an id-ad-caIssuers
	@DisplayName("PKIX.22 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_22(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);
				
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
       
        byte[] extVal = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
        assertNotNull(extVal);
        
    	try {
			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
	        assertNotNull(aia);
			
	        boolean caIssuersPresent = false;
			AccessDescription[] descriptions = aia.getAccessDescriptions();
			for (AccessDescription ad : descriptions) {
			    if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
			    	caIssuersPresent = true;
			    }
			}
			
			assertTrue(caIssuersPresent);
		} catch (IOException e) {
			fail(e);
		}
	}
	
	//The authorityInfoAccess field contains an id-ad-caIssuers
	@DisplayName("PKIX.23 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_23(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);
				
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
       
        byte[] extVal = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
        assertNotNull(extVal);
        
    	try {
			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
	        assertNotNull(aia);
			
	        boolean uriOK = false;
			AccessDescription[] descriptions = aia.getAccessDescriptions();
			for (AccessDescription ad : descriptions) {
			    if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
			        GeneralName location = ad.getAccessLocation();
			        if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
			            String url = location.getName().toString();
			            
			            if(url.startsWith("http"))
			            	uriOK = true;
			        }
			    }
			}
			
			assertTrue(uriOK);
		} catch (IOException e) {
			fail(e);
		}
	}
        
	//Check CRL DP and AIA URI for ".crl" or ".p7c"
	@DisplayName("PKIX.24 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider2")
    void PKIX_Test_24(X509Certificate cert, String oid, TestReporter reporter) {
		assertNotNull(cert);
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
       
        byte[] extVal = cert.getExtensionValue(oid);
        assertNotNull(extVal);
        
        if(oid.compareTo("1.3.6.1.5.5.7.1.1") == 0) {
        	try {
				AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
		        assertNotNull(aia);
				
				AccessDescription[] descriptions = aia.getAccessDescriptions();
				for (AccessDescription ad : descriptions) {
				    if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
				        GeneralName location = ad.getAccessLocation();
				        if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
				            String url = location.getName().toString();
				            
				            assertTrue(url.endsWith(".p7c"));
				        }
				    }
				}
			} catch (IOException e) {
				fail(e);
			}
        }
        
        if(oid.compareTo("2.5.29.31") == 0) {
        	try {
        		
        		CRLDistPoint crlDP = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
        		assertNotNull(crlDP);
        		
        		DistributionPoint[] descriptions = crlDP.getDistributionPoints();
				for (DistributionPoint dp : descriptions) {
					DistributionPointName dp_name = dp.getDistributionPoint();
					 if (dp_name.getType() == DistributionPointName.FULL_NAME)
			            {
			                GeneralName[] generalNames = GeneralNames.getInstance(dp_name.getName()).getNames();
			                for (int j = 0; j < generalNames.length; j++)
			                {
			                    if (generalNames[j].getTagNo() == GeneralName.uniformResourceIdentifier)
			                    {
			                        String url = ((DERIA5String) generalNames[j].getName()).getString();
			                        assertTrue(url.endsWith(".crl"));
			                    }
			                }
			            }
				}
			} catch (IOException e) {
				fail(e);
			}
        }
    }
	
	//The authorityInfoAccess field points to a file that has an extension of ".p7c" containing a
	//certs-only CMS message
	@DisplayName("PKIX.25 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pKIX_x509TestProvider")
    void PKIX_Test_25(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert);
				
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
       
        byte[] extVal = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
        assertNotNull(extVal);
        
    	try {
			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
	        assertNotNull(aia);
	        
			AccessDescription[] descriptions = aia.getAccessDescriptions();
			for (AccessDescription ad : descriptions) {
			    if (ad.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
			        GeneralName location = ad.getAccessLocation();
			        if (location.getTagNo() == GeneralName.uniformResourceIdentifier) {
			            String url = location.getName().toString();
			            
			            try (BufferedInputStream in = new BufferedInputStream(new URL(url).openStream());
			            		ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
		            		    byte dataBuffer[] = new byte[1024];
		            		    int bytesRead;
		            		    while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
		            		    	baos.write(dataBuffer, 0, bytesRead);
		            		    }
		            		    
		            		    ByteArrayInputStream bIn = new ByteArrayInputStream(baos.toByteArray());
		            		    ASN1InputStream aIn = new ASN1InputStream(bIn);
		                        ContentInfo contentInfo = ContentInfo.getInstance(aIn.readObject());
		                        aIn.close();
		                        try {
									CMSSignedData sd = new CMSSignedData(contentInfo);
									
									Store<X509CertificateHolder> certStore = sd.getCertificates();
									
									Collection<X509CertificateHolder> certCollection = certStore.getMatches(null);
									
									Iterator<X509CertificateHolder> certIt = certCollection.iterator();
							        	
									while(certIt.hasNext()) {
										
										X509CertificateHolder certificateHolder = (X509CertificateHolder)certIt.next();
										byte[] certBuff = certificateHolder.getEncoded();
										
										CertificateFactory certFactory;
										try {
											certFactory = CertificateFactory.getInstance("X.509");
										
											InputStream in2 = new ByteArrayInputStream(certBuff);
											X509Certificate cert2 = (X509Certificate)certFactory.generateCertificate(in2);
											
											assertNotNull(cert2);
										} catch (CertificateException e) {
											fail(e);
										}
								    }
									
								} catch (CMSException e) {
									fail(e);
								}
		                        
		            		} catch (IOException e) {
		            		    fail(e);
		            		}
			        }
			    }
			}
			
		} catch (IOException e) {
			fail(e);
		}
	}

	//check expiration date of content signing cert.
	@DisplayName("PKIX.26 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("pkix_CHUIDTestProvider")
    void PKIX_Test_26(String oid, TestReporter reporter) {
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
	
	private static Stream<Arguments> pKIX_x509TestProvider() {

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
		boolean  decoded = o1.decode();
		assert ( decoded == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, o2);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded  = o2.decode();
		assert ( decoded == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, o3);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded  = o3.decode();
		assert ( decoded == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, o4);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded  = o4.decode();
		assert ( decoded == true);
			
		result = piv.pivGetData(c, APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, o5);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded  = o5.decode();
		assert ( decoded == true);

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

		return Stream.of(Arguments.of(cert1),Arguments.of(cert2),Arguments.of(cert3),Arguments.of(cert4),Arguments.of(cert5));

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

		return Stream.of(Arguments.of(cert1, "1.3.6.1.1.16.4"),Arguments.of(cert2, "1.3.6.1.1.16.4"),Arguments.of(cert3, "1.3.6.1.1.16.4"),
				Arguments.of(cert4, "1.3.6.1.1.16.4"),Arguments.of(cert5, "1.3.6.1.1.16.4"));

	}
	
	private static Stream<Arguments> pKIX_x509TestProvider3() {

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
		boolean decoded = o1.decode();
		assert ( decoded == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, o2);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded = o2.decode();
		assert ( decoded == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, o3);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded = o3.decode();
		assert ( decoded == true);
		
		result = piv.pivGetData(c, APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, o4);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded = o4.decode();
		assert ( decoded == true);
			
		result = piv.pivGetData(c, APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, o5);
		assert (result == MiddlewareStatus.PIV_OK);
		decoded = o5.decode();
		assert ( decoded == true);

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

		return Stream.of(Arguments.of(cert1, 6),Arguments.of(cert2, 6),Arguments.of(cert3, 6),
				Arguments.of(cert4, 6),Arguments.of(cert5, 6));

	}
	
	private static Stream<Arguments> pKIX_PIVAuthx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID));
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
	
	private static Stream<Arguments> pKIX_PIVAuthx509TestProvide2() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "2.16.840.1.101.3.2.1.48.11"));

	}
	
	private static Stream<Arguments> pKIX_CardAuthx509TestProvider2() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "2.16.840.1.101.3.2.1.48.13"));

	}

	private static Stream<Arguments> pkix_CHUIDTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}
}
