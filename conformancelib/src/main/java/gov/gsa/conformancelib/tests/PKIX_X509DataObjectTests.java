package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;

public class PKIX_X509DataObjectTests {
	
	
	private static final Logger s_logger = LoggerFactory.getLogger(PKIX_X509DataObjectTests.class);

	// Verify signature algorithm conforms to 78.1, 78.2, 78.3
	@DisplayName("PKIX.1 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_1(String oid, TestReporter reporter) {
		X509Certificate cert = AtomHelper.getCertificateForContainer(oid);
		assertNotNull(cert, "Certificate could not be read for " + oid);

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
	        assertTrue(supportedCurve.compareTo(curveFromCert) == 0, "Curve retrived from the certificate " + curveFromCert +  " does not match acceptable curve " + supportedCurve);
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
		assertTrue(present, "Signature algorithm from the certificate " + sigAlgFromCert + " is not in the acceptable list " + algList.toString() );
		
	}

	// Confirm keyUsage extension is present
	@DisplayName("PKIX.2 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_2(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "NULL certificate passed to atom");

		assertTrue(cert.getKeyUsage() != null, "Key usage extension is absent");
	}

	// Confirm digitalSignature bit is set
	@DisplayName("PKIX.3 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_PIVAuthx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_3(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");

		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// taken out and placed somewhere else?
		// Confirm digitalSignature bit is set
		assertTrue(ku[0] == true, "digitalSignature bit is not set");

	}

	// Confirm no other bits are set
	@DisplayName("PKIX.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_PIVAuthx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_4(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// Confirm digitalSignature bit is set
		assertTrue(ku[0] == true, "digitalSignature bit is not set");
		assertTrue(ku[1] == false, "nonRepudiation bit is set");
		assertTrue(ku[2] == false, "keyEncipherment bit is set");
		assertTrue(ku[3] == false, "dataEncipherment bit is set");
		assertTrue(ku[4] == false, "keyAgreement bit is set");
		assertTrue(ku[5] == false, "keyCertSign bit is set");
		assertTrue(ku[6] == false, "cRLSign bit is set");
		assertTrue(ku[7] == false, "encipherOnly bit is set");
		assertTrue(ku[7] == false, "decipherOnly bit is set");

	}

	// Confirm certificate policies extension is present
	@DisplayName("PKIX.5 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_5(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");

		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null, "Certificate policies extension is absent");
		
    }
	
	// Confirm that id- fpki-common-authentication 2.16.840.1.101.3.2.1.3.13 OID (or PIV-I or ICAM Test equivalent)
	// is asserted in certificate policies (parameters required)
	@DisplayName("PKIX.6 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_PIVAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_6(String oid, String policyOid, TestReporter reporter) {
		
		if (policyOid == null) {
			ConformanceTestException e  = new ConformanceTestException("policyOid is null");
			fail(e);
		}
		List<String> paramList = Arrays.asList(policyOid.split(","));
		
		HashMap<String,List<String>> rv = new HashMap<String,List<String>>();
		
		for(String p : paramList) {
			String[] paramList2 = p.split(";");
					
			List<String> paramList3 = Arrays.asList(paramList2[1].split(":"));
			String containerOid = APDUConstants.getStringForFieldNamed(paramList2[0]);
			rv.put(containerOid, paramList3);
		}
				
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		X509Certificate cert = null;
		if(oid.compareTo(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID) != 0) {

			cert = ((X509CertificateDataObject) o).getCertificate();
		} else {
			cert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		}
       
		
		if (cert == null) {
			ConformanceTestException e  = new ConformanceTestException("Certificate retrived from X509CertificateDataObject object is NULL");
			fail(e);
		}

		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null, "Certificate policies extension is absent");
		
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
	    	if(rv.get(oid).contains(curroid.getId())) {
	    		containsOOID = true;
	    		break;
	    	}
	    }
	    
	    //Confirm that oid matches is asserted in certificate policies
	    assertTrue(containsOOID, "Policy oid " + policyOid + " is not present in certificate policies");
    }
	
	/* ******************* Standard stuff for most all certs ************************ */
	
	//Confirm that authorityInformationAccess extension is present
	@DisplayName("PKIX.7 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_7(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "NULL certificate passed to atom");

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null, "AIA extension is not present");
	}
	
	//Confirm that an access method containing id-ad-ocsp is present (only PIV auth requires this)
	@DisplayName("PKIX.8 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_8(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "NULL certificate passed to atom");

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		if (aiaex != null) {
			AuthorityInformationAccess aia = null;
			try {
				aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(aiaex));
				
				if (aia != null) {
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
			        assertTrue(ocsppresent, "id-ad-ocsp is not present");
				}
			} catch (IOException e) {
				fail(e);
			}

	    } else {
	    	ConformanceTestException e  = new ConformanceTestException("No AIA is present.");
			fail(e);
	    }
	}
	
	//Confirm that the AIA uniformResourceIdentifier protocol is http
	@DisplayName("PKIX.9 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_9(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "NULL certificate passed to atom");

		boolean uriOk = false;
		
		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
		
		if (aiaex != null) {
			AuthorityInformationAccess aia = null;
			
			try {
				aia = AuthorityInformationAccess.getInstance(X509ExtensionUtil.fromExtensionValue(aiaex));
				if (aia != null) {
					AccessDescription[] ads = aia.getAccessDescriptions();
			        for (int i = 0; i < ads.length; i++)
			        {
			            if (ads[i].getAccessMethod().equals(AccessDescription.id_ad_ocsp))
			            {
			            	GeneralName gn = ads[i].getAccessLocation();
			            	
			            	if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
				                String url = ((DERIA5String) gn.getName()).getString();
				
				                assertTrue(url.startsWith("http:"), "OCSP url does not start with http " + url);
				            	uriOk = true;
			            	}
			            }
			        }
				}
			} catch (IOException e) {
				fail(e);
			}
		} else {
	    	ConformanceTestException e  = new ConformanceTestException("No AIA is present.");
			fail(e);			
		}

        //Confirm URI is http
        assertTrue(uriOk);
    }
	
	//Confirm that piv interim "2.16.840.1.101.3.6.9.1" extension is present
	@DisplayName("PKIX.10 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_PIVAuthx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_10(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();

		if (cert != null) {
			//Get piv interim "2.16.840.1.101.3.6.9.1" extension
			byte[] pivInterim = cert.getExtensionValue("2.16.840.1.101.3.6.9.1");
			
			//Confirm pivInterim extension is present and isn't empty
			assertTrue(pivInterim != null, "pivInterim extension is not present");
			assertTrue(pivInterim.length > 0, "pivInterim extension is empty");
		} else {
        	ConformanceTestException e  = new ConformanceTestException("Could not obtain certificate for " + oid);
			fail(e);
		}

    }
	
	//Sign arbitrary data using the specified key container and confirm that the certificate can validate it
	@DisplayName("PKIX.11 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_11(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "NULL certificate passed to atom");
		// issue #107... temporarily turning red all the time to avoid repeat
		ConformanceTestException e = new ConformanceTestException("PKIX.11 needs to always fail until 107 is addressed.");
		fail(e);
		/*
		KeyValidationHelper kvh = KeyValidationHelper.getInstance();
		try {
			kvh.validateKey(cert, oid);
			s_logger.error("validateKey() finished");
		} catch(ConformanceTestException cte) {
			fail(cte);
		}
		*/
    }
	
	//Confirm that the certificate subjectAltName includes FASC-N and that it matches CHUID
	@DisplayName("PKIX.12 test")
    @ParameterizedTest(/*name = "{index} => oid = {0}"*/)
    //@MethodSource("pKIX_x509TestProvider2")
    //@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@ArgumentsSource(gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider.class)
    void PKIX_Test_12(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		
		//Check that the oid passed in is not null
		if (cert == null) {
			ConformanceTestException e  = new ConformanceTestException("certificate is null");
			fail(e);
		}
		
		//Check that the oid passed in is not null
		if (oid == null) {
			ConformanceTestException e  = new ConformanceTestException("OID is null");
			fail(e);
		}
		
		
		PIVDataObject o2 = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);

               
		byte[] fascn = ((CardHolderUniqueIdentifier) o2).getfASCN();
		
		try {
			Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
	        if (altNames != null) {
	            for (List<?> altName : altNames) {
	                Integer altNameType = (Integer) altName.get(0);
	                if (altNameType == 0) {
	                	byte[] otherName = (byte[]) altName.toArray()[1];
               	
	                	byte[] fascnFromCert = Arrays.copyOfRange(otherName, 18, otherName.length);
	                	assertTrue(Arrays.equals(fascnFromCert, fascn), "FASCN values do not match");
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
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_13(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		if (cert == null) {
			ConformanceTestException e  = new ConformanceTestException("certificate is null");
			fail(e);
		}
		
		PIVDataObject o2 = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);

		Date notAfter =  cert.getNotAfter();
		assertNotNull(notAfter);
		
		Date expirationDate = ((CardHolderUniqueIdentifier) o2).getExpirationDate();
                GregorianCalendar gc = new GregorianCalendar();
                gc.setTime(expirationDate);
                gc.add(Calendar.HOUR, 23);
                gc.add(Calendar.MINUTE, 59);
                gc.add(Calendar.SECOND, 59);
                Date exactDateTime = gc.getTime();
				
		//Confirm that expiration of certificate is not later than expiration of card
                assertTrue(notAfter.compareTo(exactDateTime) <= 0, "Certificate " + notAfter + " expires later than the card " + exactDateTime);

    }

	//For RSA certs, confirm that public exponent >= 65537
	@DisplayName("PKIX.14 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_14(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		if (cert == null) {
			ConformanceTestException e  = new ConformanceTestException("certificate is null");
			fail(e);
		}
		assertNotNull(cert, "NULL certificate passed to atom");

		RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
		
		
		BigInteger be = BigInteger.valueOf(65537);
		
		if(pubKey instanceof RSAPublicKey) {
			//confirm that public exponent >= 65537
			assertTrue(pubKey.getPublicExponent().compareTo(be) >= 0, "Public exponent is not >= 65537" );
		} 
    }
	
	//Confirm digitalSignature and nonRepudiation bits are set
	@DisplayName("PKIX.15 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_DigSigx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_15(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
        X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");

		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// taken out and placed somewhere else?
		// Confirm digitalSignature and nonRepudiation bit is set
		assertTrue(ku[0] == true, "digitalSignature bit is not set");
		assertTrue(ku[1] == true, "nonRepudiation bit is not set");
    }
	
	
	//Confirm Key Management certificates for RSA keys have keyEncipherment bit set
	@DisplayName("PKIX.16 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_KeyMgmtx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_16(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");

		boolean[] ku = cert.getKeyUsage();

		// confirm key usage extension is present
		assertTrue(ku != null);

		// taken out and placed somewhere else?
		// Confirm keyEncipherment bit is set
		assertTrue(ku[2] == true, "keyEncipherment bit is not set");
    }
	
	//Confirm Key Management certificates for elliptic curve keys have keyAgreement bit set 
	@DisplayName("PKIX.17 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_KeyMgmtx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_17(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		PublicKey pubKey = cert.getPublicKey();

		if(pubKey instanceof ECPublicKey) {
		
			boolean[] ku = cert.getKeyUsage();

			// confirm key usage extension is present
			assertTrue(ku != null, "Key usage extension is absent");
			// Confirm keyAgreement bit is set
			assertTrue(ku[4] == true, "keyAgreement bit is not set");
		}
		
    }
	
	//Confirm that id- fpki-common-cardAuth 2.16.840.1.101.3.2.1.3.17 OID is asserted in certificate policies
	@DisplayName("PKIX.18 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_18(String oid, String policyOid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
        X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue("2.5.29.32");
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null, "Certificate policies extension is absent");
		
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
	    assertTrue(containsOOID, "Certificate policy " + policyOid + " is not present in certificate policies on the certificate");
		
    }
	
	//Confirm extendedKeyUsage extension is present
	@DisplayName("PKIX.19 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_19(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		//Get eku extension
		byte[] cpex = cert.getExtensionValue("2.5.29.37");
		
		//Confirm eku extension is present
		assertTrue(cpex != null, "EKU extension is absent");
    }

	//Confirm id-PIV-cardAuth 2.16.840.1.101.3.6.8 exists in extendedKeyUsage extension
	@DisplayName("PKIX.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_20(String oid, String ekuOid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		//Get certificate policies extension
		byte[] ekuex = cert.getExtensionValue("2.5.29.37");
		
		//Confirm certificate policies extension is present
		assertTrue(ekuex != null, "Certificate policies extension is absent");
		
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
	    assertTrue(containsOOID, "EKU does not contain " + ekuOid);
		
    }

	@DisplayName("PKIX.21 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_21(String oid, String ekuOid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
		//Get certificate policies extension
		byte[] ekuex = cert.getExtensionValue("2.5.29.37");
		
		//Confirm certificate policies extension is present
		assertTrue(ekuex != null, "Certificate policies extension is absent");
		
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
	    
	    assertTrue(containsOOID, "EKU does not contain " + ekuOid);
	}

	void PKIX_Test_22x(X509Certificate cert, TestReporter reporter) {
		assertNotNull(cert, "NULL certificate passed to atom");
				
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
       
        byte[] extVal = cert.getExtensionValue("2.5.29.31");
        
        if (extVal != null) {		
	    	try {		
	    		CRLDistPoint crlDP = CRLDistPoint.getInstance(X509ExtensionUtil.fromExtensionValue(extVal));
	    		assertNotNull(crlDP);
	    		
	    		DistributionPoint[] descriptions = crlDP.getDistributionPoints();
				for (DistributionPoint dp : descriptions) {
					DistributionPointName dp_name = dp.getDistributionPoint();
					if (dp_name.getType() == DistributionPointName.FULL_NAME) {
		                GeneralName[] generalNames = GeneralNames.getInstance(dp_name.getName()).getNames();
		                for (int j = 0; j < generalNames.length; j++)
		                {
		                    if (generalNames[j].getTagNo() == GeneralName.uniformResourceIdentifier)
		                    {
		                        String url = ((DERIA5String) generalNames[j].getName()).getString();
		                        assertTrue(url.endsWith(".crl"), "CRL DP url does not end with .crl");
		                    }
		                }
		            }
				}
			} catch (IOException e) {
				fail(e);
			}
        } else {
        	ConformanceTestException e  = new ConformanceTestException("No CRL distribution point present.");
        	fail(e);
        }
	}
	
	//The authorityInfoAccess field contains an id-ad-caIssuers (1.3.6.1.5.5.7.48.2) accessMethod
	@DisplayName("PKIX.22 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_22(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
				
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
	    if (extVal != null) {
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
				
				assertTrue(caIssuersPresent, "id-ad-caIssuers is missing from AIA");
			} catch (IOException e) {
				fail(e);
			}
        } else {
        	ConformanceTestException e  = new ConformanceTestException("No AIA present.");
        	fail(e);
        }
	}
	
	//URI scheme is http:
	@DisplayName("PKIX.23 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_23(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
				
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
        
        if (extVal != null) {  
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
				            
				            if(url.startsWith("http:"))
				            	uriOK = true;
				        }
				    }
				}
				
				assertTrue(uriOK, "AIA url does not start with http");
			} catch (IOException e) {
				fail(e);
			}
        } else {
        	ConformanceTestException e  = new ConformanceTestException("No AIA extension present.");
			fail(e);
        }
	}
        
	//Check CRL DP and AIA URI for ".crl" or ".p7c"
	@DisplayName("PKIX.24 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_24(String containerOid, String oid, TestReporter reporter) {
		assertNotNull(containerOid, "NULL certificate passed to atom");
		assertNotNull(oid, "NULL oid passed to atom");
		PIVDataObject o = AtomHelper.getDataObject(containerOid);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
				 
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
				            
				            assertTrue(url.endsWith(".p7c"), "AIA caIssuers url does not end with .p7c " + url);
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
        		boolean gotHttp = true;
				for (DistributionPoint dp : descriptions) {
					DistributionPointName dp_name = dp.getDistributionPoint();
					if (dp_name.getType() == DistributionPointName.FULL_NAME) {
		                GeneralName[] generalNames = GeneralNames.getInstance(dp_name.getName()).getNames();
		                for (int j = 0; j < generalNames.length; j++)
		                {
		                    if (generalNames[j].getTagNo() == GeneralName.uniformResourceIdentifier)
		                    {
		                        String url = ((DERIA5String) generalNames[j].getName()).getString();
		                        if(url.startsWith("http")) {
		                        	gotHttp = true;
									assertTrue(url.endsWith(".crl"), "CRL DP url does not end with .crl " + url);
		                        }
		                    }
		                }
		            }
				}
				if(!gotHttp) {
					s_logger.warn("PKIX.24 only passed because there was no http CRLDP. PKIX.23 will fail on this DP.");
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
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_25(String oid, TestReporter reporter) {
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert, "Certificate retrived from X509CertificateDataObject object is NULL");
				      
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
			            
			            // Some SSPs will also include other URLs (e.g. LDAP) that should not cause this test to fail.
			            if(!url.startsWith("http")) continue;
			            	
			            
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
											
											assertNotNull(cert2, "Unable to parse certificate contained in the " + url);
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
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		
		X509Certificate cert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		Calendar cal = Calendar.getInstance();
		Date today = cal.getTime();
		
		assertTrue(cert.getNotAfter().compareTo(today) >= 0, "Signing certificate expired " + cert.getNotAfter());
       
    }
	
	private static Map<String, X509Certificate> getCertificatesForOids(List<String> oids) {
		HashMap<String, X509Certificate> rv = new HashMap<String, X509Certificate>();
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		//if(css == null) s_logger.error("Failed to retrieve card settings singleton while constructing test parameters");
		assertNotNull(css, "Failed to get instance of Card Settings Singleton");
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

		AbstractPIVApplication piv = css.getPivHandle();
		CardHandle c = css.getCardHandle();
		MiddlewareStatus result = MiddlewareStatus.PIV_OK;
		
		assertNotNull(piv, "Invalid PIV application handle in singleton");
		assertNotNull(c, "Invalid card handle in singleton");
		
		for(String oid : oids) {
			//s_logger.debug("Retrieving certificate for oid {}", oid);
			PIVDataObject obj = PIVDataObjectFactory.createDataObjectForOid(oid);
			assertNotNull(obj, "Failed to allocate PIV data object");
			result = piv.pivGetData(c, oid, obj);
			if(result != MiddlewareStatus.PIV_OK) {
				// this is only a warning here because it is up to the consumer of this function to decide
				// whether a missing cert constitutes an assertion failure
				//s_logger.warn("pivGetData() for {} returned {}", oid, result);
				rv.put(oid, null);
			}
			boolean  decoded = obj.decode();
			assertTrue(decoded, "Failed to decode object for OID " + oid);
			X509Certificate cert = null;
			if(oid.equals(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID)) {
				CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) obj;
				cert = chuid.getSigningCertificate();
			} else {
				X509CertificateDataObject certObject = (X509CertificateDataObject) obj;
				cert = certObject.getCertificate();
			}
			rv.put(oid, cert);
		}
		return rv;
	}
	
	// The local provider methods are now only used to test the atoms... they are no longer operative in the conformance tool
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_x509TestProvider() {
		
		PIVDataObject o1 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
		PIVDataObject o2 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
		PIVDataObject o3 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
		PIVDataObject o4 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);		
		PIVDataObject o5 = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);

		X509Certificate cert1 = ((X509CertificateDataObject) o1).getCertificate();
		assertNotNull(cert1, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert2 = ((X509CertificateDataObject) o2).getCertificate();
		assertNotNull(cert2, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert3 = ((X509CertificateDataObject) o3).getCertificate();
		assertNotNull(cert3, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert4 = ((X509CertificateDataObject) o4).getCertificate();
		assertNotNull(cert4, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert5 = ((CardHolderUniqueIdentifier) o5).getSigningCertificate();
		assertNotNull(cert5, "Certificate retrived from X509CertificateDataObject object is NULL");

		return Stream.of(Arguments.of(cert1),Arguments.of(cert2),Arguments.of(cert3),Arguments.of(cert4),Arguments.of(cert5));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_x509TestProvider_aia_crldp() {
		ArrayList<String> certContainersToTest = new ArrayList<String>();
		certContainersToTest.add(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
		certContainersToTest.add(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
		certContainersToTest.add(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
		certContainersToTest.add(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
		certContainersToTest.add(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		
		Map<String, X509Certificate> certificates = getCertificatesForOids(certContainersToTest);
		
		String aiaOid = "1.3.6.1.5.5.7.1.1";
		String crldpOid = "2.5.29.31";
		
		Stream.Builder<Arguments> generator = Stream.builder();
		for(String oid : certContainersToTest) {
			X509Certificate cert = certificates.get(oid);
			assertNotNull(cert, "Certificate for container " + oid + " was not found.");
			generator.add(Arguments.of(cert, aiaOid));
			generator.add(Arguments.of(cert, crldpOid));
		}
		return generator.build();
	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_x509TestProvider2() {
		
		PIVDataObject o1 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
		PIVDataObject o2 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
		PIVDataObject o3 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
		PIVDataObject o4 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);		
		PIVDataObject o5 = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);


		X509Certificate cert1 = ((X509CertificateDataObject) o1).getCertificate();
		assertNotNull(cert1, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert2 = ((X509CertificateDataObject) o2).getCertificate();
		assertNotNull(cert2, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert3 = ((X509CertificateDataObject) o3).getCertificate();
		assertNotNull(cert3, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert4 = ((X509CertificateDataObject) o4).getCertificate();
		assertNotNull(cert4, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert5 = ((CardHolderUniqueIdentifier) o5).getSigningCertificate();
		assertNotNull(cert5, "Certificate retrived from X509CertificateDataObject object is NULL");

		return Stream.of(Arguments.of(cert1, "1.3.6.1.1.16.4"),Arguments.of(cert2, "1.3.6.1.1.16.4"),Arguments.of(cert3, "1.3.6.1.1.16.4"),
				Arguments.of(cert4, "1.3.6.1.1.16.4"),Arguments.of(cert5, "1.3.6.1.1.16.4"));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_x509TestProvider3() {

		PIVDataObject o1 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
		PIVDataObject o2 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
		PIVDataObject o3 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
		PIVDataObject o4 = AtomHelper.getDataObject(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);		
		PIVDataObject o5 = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);


		X509Certificate cert1 = ((X509CertificateDataObject) o1).getCertificate();
		assertNotNull(cert1, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert2 = ((X509CertificateDataObject) o2).getCertificate();
		assertNotNull(cert2, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert3 = ((X509CertificateDataObject) o3).getCertificate();
		assertNotNull(cert3, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert4 = ((X509CertificateDataObject) o4).getCertificate();
		assertNotNull(cert4, "Certificate retrived from X509CertificateDataObject object is NULL");
		
		X509Certificate cert5 = ((CardHolderUniqueIdentifier) o5).getSigningCertificate();
		assertNotNull(cert5, "Certificate retrived from X509CertificateDataObject object is NULL");

		return Stream.of(Arguments.of(cert1, 6),Arguments.of(cert2, 6),Arguments.of(cert3, 6),
				Arguments.of(cert4, 6),Arguments.of(cert5, 6));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_PIVAuthx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
				Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID));
	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_DigSigx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_KeyMgmtx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_CardAuthx509TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_PIVAuthx509TestProvider2() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, "2.16.840.1.101.3.2.1.48.11"));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> pKIX_CardAuthx509TestProvider2() {

		return Stream.of(Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, "2.16.840.1.101.3.2.1.48.13"));

	}

	@SuppressWarnings("unused")
	private static Stream<Arguments> pkix_CHUIDTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}
}
