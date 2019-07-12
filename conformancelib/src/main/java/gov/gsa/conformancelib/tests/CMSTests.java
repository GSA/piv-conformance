package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Store;

import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import javax.security.auth.x500.X500Principal;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Collection;
import java.util.Enumeration;
import java.io.IOException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.CardholderBiometricData;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.SecurityObject;

public class CMSTests {
	static Logger s_logger = LoggerFactory.getLogger(CMSTests.class);

	//Verify that the asymmetric digital field contains a CMS signed data object with no encapsulated content
	@DisplayName("CMS.1 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_1(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm that no encapsulated content present
		assertTrue(issuerAsymmetricSignature.isDetachedSignature());
    }
	
	//Verify that version is set to 3
	@DisplayName("CMS.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_2(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm version is 3
		assertTrue(issuerAsymmetricSignature.getVersion() == 3);
    }
	
	//Validate signing key length
	@DisplayName("CMS.3 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_3(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		assertNotNull(signingCert);
		
		PublicKey pubKey = signingCert.getPublicKey();
		
		if(pubKey instanceof RSAPublicKey) {
			RSAPublicKey pk = (RSAPublicKey) pubKey;
			assertTrue(pk.getModulus().bitLength() == 2048);
		} 
		
		if(pubKey instanceof ECPublicKey) {
			
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
	        
	        //Confirm that the curve in the signing certificate is prime256v1
	        assertTrue(supportedCurve.compareTo(curveFromCert) == 0);
		}
    }

	//Verify digestAlgorithms attribute is present
	@DisplayName("CMS.4 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_4(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
    }
	
	//Ensure encapsulated content is absent
	@DisplayName("CMS.5 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_5(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			//Confirm encapsulated content is absent
			assertTrue(issuerAsymmetricSignature.getSignedContent() == null, "encapsulated content is NOT absent");
			
			String contentType = issuerAsymmetricSignature.getSignedContentTypeOID();
			//Confirm that content type is  id-PIV-CHUIDSecurityObject
			assertTrue(contentType.compareTo("2.16.840.1.101.3.6.1") == 0, "eContentType is NOT id-piv-CHUIDSecurityObject");
		}
		catch (Exception e) {
			fail(e);
		}
		
    }
	
	
	//Ensure CRLs field is absent in signed data structure
	@DisplayName("CMS.6 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_6(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		//Confirm encapsulated content is absent
		assertTrue(issuerAsymmetricSignature.isDetachedSignature());
		
		Store<?> crlStore = issuerAsymmetricSignature.getCRLs();
		
		
		Collection<?> crlColl = crlStore.getMatches(null);
		
		assertTrue(crlColl.size() == 0);
    }
	
	//Verify SignerInfos contains only a single signerInfo
	@DisplayName("CMS.7 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_7(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		
		//Confirm only one signer is present
		assertTrue(signers.size() == 1);

    }
	
	//Ensure that the signerId uses ths IssuerAndSerialNumber choice
	@DisplayName("CMS.8 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_8(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		

		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			SignerId signerId = signer.getSID();
			
			//Confirm issuer and serial number are present 
			assertNotNull(signerId.getIssuer());
			assertNotNull(signerId.getSerialNumber());
			
			//Confirm SKID is absent
			assertTrue(signerId.getSubjectKeyIdentifier() == null);
			
		}		
    }
	
	//Ensure that the Issuer in the signer info corresponds to the issuer value in the signer's certificate
	@DisplayName("CMS.9 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_9(String oid, TestReporter reporter) {
    	try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
			if (signingCert == null) {
				Exception e = new Exception("Signing Certificate is null");
				throw e;
			}
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("signers is null");
				throw e;
			}
	
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
	
				SignerId signerId = signer.getSID();
				if (signerId.getIssuer() == null) {
					Exception e = new Exception("issuer is null");
					throw e;
				}
				Principal issuerFromCert = signingCert.getIssuerDN();
				X500Name tmp = new X500Name(issuerFromCert.getName());
				X500NameStyle style = RFC4519Style.INSTANCE;
				//Confirm issuer from the cert matcher issuer from the signer info
				assertTrue(style.areEqual(signerId.getIssuer(), tmp));
				
			}
    	}
    	catch (Exception e) {
    		fail(e);
    	}
    }
	
	//Confirm that piv interim extension is present
	@DisplayName("CMS.10 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_10(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		assertNotNull(signingCert);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		
		//XXX Two questions about this tests.  Is the extension need to be found in the signing certificate?  What is the oid for piv interum 
		byte[] pivInterim = signingCert.getExtensionValue("2.5.29.32");
		
		//Confirm the extension is not null
		assertNotNull(pivInterim);
    }
	
	//Validate that message digest from signed attributes bag matches the digest over CHUID (excluding contents of digital signature field)
	@DisplayName("CMS.11 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_11(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		assertNotNull(signingCert);
		

		//Signature verification confirms that message digest from signed attributes bag matches the digest over CHUID
		assertTrue(((CardHolderUniqueIdentifier) o).verifySignature());
    }
	
	//Validate that signed attributes includes pivSigner-DN 
	@DisplayName("CMS.12 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_12(String oid, TestReporter reporter) {
		
    	try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
			if (signingCert == null) {
				Exception e = new Exception("Signing Certificate is null");
				throw e;
			}
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("signers is null");
				throw e;
			}
	
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
	
				SignerId signerId = signer.getSID();
				if (signerId == null) {
					Exception e = new Exception("signerId is null");
					throw e;
				}
				AttributeTable attributeTable = signer.getSignedAttributes();
				if (attributeTable == null) {
					Exception e = new Exception("attributeTable is null");
					throw e;
				}
				
				ASN1ObjectIdentifier pivSigner_DN = new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
				Attribute attr = attributeTable.get(pivSigner_DN);
				assertNotNull(attr);
			}
    	}
    	catch (Exception e) {
    		fail(e);
    	}
    }
	
	
	//Verify permissibility of signature algorithm relative to sunset date
	@DisplayName("CMS.13 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_13(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		assertNotNull(signingCert);
		
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);

        List<String> digestAlgList = new ArrayList<String>();
        
        digestAlgList.add("2.16.840.1.101.3.4.2.1");
        
        List<String> encryptionAlgList = new ArrayList<String>();
        
        encryptionAlgList.add("1.2.840.113549.1.1.1");
        
		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			
			String algOID1 = signer.getDigestAlgOID();
			String algOID2 = signer.getEncryptionAlgOID();
			
			assertTrue(digestAlgList.contains(algOID1));
			assertTrue(encryptionAlgList.contains(algOID2));
		}	
    }
	
	//Confirm that the certificate from the cert bag successfully validates the CMS signature
	@DisplayName("CMS.14 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
    void CMS_Test_14(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		assertNotNull(signingCert);
		

		Store<X509CertificateHolder> certBag = issuerAsymmetricSignature.getCertificates();
		
		assertNotNull(certBag);
		assertTrue(certBag.getMatches(null).size() > 0);
		
		Collection<X509CertificateHolder> certCollection = certBag.getMatches(null);
		
		Iterator<X509CertificateHolder>        certIt = certCollection.iterator();
        X509CertificateHolder cert = (X509CertificateHolder)certIt.next();
        
        try {
        	//Set the signing cert to the one from the cert bag
			((CardHolderUniqueIdentifier) o).setSigningCertificate(new JcaX509CertificateConverter().setProvider( "BC" ).getCertificate( cert ));
		} catch (CertificateException e) {
			fail(e);
		}
		
		assertTrue(((CardHolderUniqueIdentifier) o).verifySignature());
    }
	
	//Confirm that signing certificate contains id-PIV-content-signing (2.16.840.1.101.3.6.7) in EKU extension
	@DisplayName("CMS.15 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_15(String container, String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(container);
		
		CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
		X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(issuerAsymmetricSignature);
		assertNotNull(signingCert);
		
		SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		
		List<String> ekuList = new ArrayList<String>();
		try {
			ekuList = signingCert.getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			fail(e);
		}
		
		//Confirm id-PIV-content-signing (2.16.840.1.101.3.6.7) present
		assertTrue(ekuList.contains(oid));
    }
	
	//Validate that message digest from signed attributes bag matches the digest over Fingerprint biometric data (excluding contents of digital signature field)
	@DisplayName("CMS.16 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	//@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_16(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		PIVDataObject o2 = AtomHelper.getDataObjectWithAuth(APDUConstants.CARDHOLDER_FINGERPRINTS_OID);
                	
        HashMap<String, byte[]> soDataElements = new  HashMap<String, byte[]>();
        
        boolean decoded = o.decode();
		assertTrue(decoded);
				
		soDataElements.put(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, ((CardholderBiometricData) o2).getCceffContainer());
		
		((SecurityObject) o).setMapOfDataElements(soDataElements);
		
		//Confirm that message digest from signed attributes bag matches the digest over Fingerprint biometric data (excluding contents of digital signature field) 
		assertTrue(((SecurityObject) o).verifyHashes());
		
    }
	
	//Confirm that signed attributes include pivFASC-N attribute and that it matches FACSC-N read from CHUID container
	@DisplayName("CMS.17 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_17(String oid, String params, TestReporter reporter) {
		try {
			String[] oidList = params.split(",");
			boolean isMandatory = APDUConstants.isContainerMandatory(oid);
			if(!isMandatory && !AtomHelper.isDataObjectPresent(oid, true)) {
				s_logger.info("Optional container {} is absent from the card.", oid);
				return;
			}
			PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
			CardHolderUniqueIdentifier chuid = (CardHolderUniqueIdentifier) AtomHelper.getDataObjectWithAuth(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
			
			//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
			CMSSignedData issuerAsymmetricSignature = AtomHelper.getSignedDataForObject(o);
			if (issuerAsymmetricSignature == null) {
				ConformanceTestException e = new ConformanceTestException("Issuer Asymmetric Signature is null");
				throw e;
			}
			/*
			 * This appears to be a holdover from a previous test
			 * byte[] fascn = ((CardHolderUniqueIdentifier) o).getfASCN();
			if (fascn == null) {
				ConformanceTestException e = new ConformanceTestException("fascn is null");
				throw e;
			}*/
			
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				ConformanceTestException e = new ConformanceTestException("signers is null");
				throw e;
			}
	
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
	
				SignerId signerId = signer.getSID();
				if (signerId == null) {
					ConformanceTestException e = new ConformanceTestException("signerId is null");
					throw e;
				}
				AttributeTable attributeTable = signer.getSignedAttributes();
				if (attributeTable == null) {
					ConformanceTestException e = new ConformanceTestException("attributeTable is null");
					throw e;
				}
				HashMap<String, Attribute> attrsFound = new HashMap<String, Attribute>();
				// XXX *** TODO: move this comparison to the CHUID object. too specific for this atom
				byte[] fascn = chuid.getfASCN();
				String fascnOid = "2.16.840.1.101.3.6.6";
				byte[] guid = chuid.getgUID();
				String guidOid = "1.3.6.1.1.16.4";
				for (int i = 0; i < oidList.length; i++) {
					String attrOid = oidList[i];
					ASN1ObjectIdentifier currAttrOid = new ASN1ObjectIdentifier(attrOid);
					Attribute attr = attributeTable.get(currAttrOid);
					assertNotNull(attr, "Expected to find " + attrOid + " for container " + oid);
					attrsFound.put(attrOid, attr);
					if(oid == guidOid) assertTrue(Arrays.equals(attr.getEncoded(), guid), "GUID from signed attribute does not match card guid");
					if(oid == fascnOid) assertTrue(Arrays.equals(attr.getEncoded(), fascn), "GUID from signed attribute does not match card guid");
					//assertNotNull(attr, "attr " + attrOid + " is null");
				}
			}
		}
		catch (Exception e) {
			fail(e);
		}
    }
	
	
	//Confirm that version of signed data structure is 1
	@DisplayName("CMS.18 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
    void CMS_Test_18(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData signedData = ((SecurityObject) o).getSignedData();

		assertTrue(signedData.getVersion() == 3);
		
    }
	
	//Verify that eContent contains a security object
	@DisplayName("CMS.19 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
    void CMS_Test_19(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData signedData = ((SecurityObject) o).getSignedData();

		assertNotNull(signedData);
		
		//Confirm encapsulated content is present
		CMSProcessableByteArray cpb = (CMSProcessableByteArray) signedData.getSignedContent();
		byte[] signedContent = (byte[]) cpb.getContent();
		assertNotNull(signedContent);
		assertTrue(signedContent.length > 0);
			
    }
	
	//Verify that eContentType is id-icao-ldsSecurityObject "2.23.136.1.1.1"
	@DisplayName("CMS.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
    void CMS_Test_20(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		CMSSignedData signedData = ((SecurityObject) o).getSignedData();

		assertNotNull(signedData);
		
		CMSTypedData ct = signedData.getSignedContent();
		
		//XXX Confirm the right oid for id-icao-ldsSecurityObject is it "2.23.136.1.1.1"  or "1.3.27.1.1.1"
		assertTrue(ct.getContentType().toString().compareTo("1.3.27.1.1.1") == 0);
    }
	
	//Confirm certificates field is omitted
	@DisplayName("CMS.21 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
    void CMS_Test_21(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData signedData = ((SecurityObject) o).getSignedData();

		assertNotNull(signedData);
		
		Store<X509CertificateHolder> certBag = signedData.getCertificates();
		
		assertNotNull(certBag);
		assertTrue(certBag.getMatches(null).size() == 0);
    }
	
	//Confirm certificate used to sign CHUID verifies signature
	@DisplayName("CMS.22 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
    void CMS_Test_22(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		PIVDataObject o2 = AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		
		X509Certificate cert = ((CardHolderUniqueIdentifier) o2).getSigningCertificate();

		assertNotNull(cert);
		
		assertTrue(((SecurityObject) o).verifySignature(cert));
    }
	
	//Validate signing and digest algorithms
	@DisplayName("CMS.23 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
    void CMS_Test_23(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		CMSSignedData signedData = ((SecurityObject) o).getSignedData();

		assertNotNull(signedData);
		
		SignerInformationStore signers = signedData.getSignerInfos();
		
		assertNotNull(signers);

        List<String> digestAlgList = new ArrayList<String>();
        
        digestAlgList.add("2.16.840.1.101.3.4.2.1");
        
        List<String> encryptionAlgList = new ArrayList<String>();
        
        encryptionAlgList.add("1.2.840.113549.1.1.1");
        
		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			
			String algOID1 = signer.getDigestAlgOID();
			String algOID2 = signer.getEncryptionAlgOID();
			
			assertTrue(digestAlgList.contains(algOID1));
			assertTrue(encryptionAlgList.contains(algOID2));
		}	
    }
	
	// Verify digest algorithm is present (extended from CMS.4)
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	@DisplayName("CMS.24 Test")
	void CMS_Test_24 (String oid, TestReporter reporter) {
		
    	try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
	
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			Set<AlgorithmIdentifier> digestAlgSet = issuerAsymmetricSignature.getDigestAlgorithmIDs();
			if (digestAlgSet == null) {
				Exception e = new Exception("digestAlgSet is null");
				throw e;
			}
			//Confirm that digestAlgorithms attribute is present and algorithm is present
			assertTrue(digestAlgSet.size() > 0);
    	}
    	catch (Exception e) {
    		fail(e);
    	}
	}
    
	// Verify that digest algorithm is consistent with the signature algorithm (split from CMS.4)
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	@DisplayName("CMS.25 Test")
	void CMS_Test_25 (String oid, TestReporter reporter) {
    	try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
				
			Set<AlgorithmIdentifier> digestAlgSet = issuerAsymmetricSignature.getDigestAlgorithmIDs();
			if (digestAlgSet == null) {
				Exception e = new Exception("digestAlgSet is null");
				throw e;
			}
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("signers is null");
				throw e;
			}
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
				AlgorithmIdentifier algID = signer.getDigestAlgorithmID();
				assertTrue(digestAlgSet.contains(algID));
			}
    	}
    	catch (Exception e) {
    		fail(e);
    	}
	}
    
	// Ensure eContentType is id-piv-CHUIDSecurityContent in encapContentInfo (split from CMS.5)
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	@DisplayName("CMS.26 Test")
	void CMS_Test_26 (String oid, TestReporter reporter) {
    	try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			//Confirm encapsulated content is absent
			if (issuerAsymmetricSignature.isDetachedSignature() == false) {
				Exception e = new Exception("isDetachedSignature is false");
				throw e;
			}
			ContentInfo contentInfo = ((CardHolderUniqueIdentifier) o).getContentInfo();
			ASN1Encodable content = contentInfo.getContent();
			//Confirm that encapsulated content is absent
			if (content != null) {
				Exception e = new Exception("content is not null");
				throw e;
			}
			ASN1ObjectIdentifier ct = contentInfo.getContentType();
			//XXX Couldn't find OID for  id-piv-CHUIDSecurityContent need to find it and put here
			assertTrue(ct.getId().compareTo("1.2.3.4.5.6.7.8.9") == 0);
    	}
    	catch (Exception e) {
    		fail(e);
    	}
	}

	// Ensure that the Serial in the signer info corresponds to the serial value in the signer certificate (split from CMS.9)
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	@DisplayName("CMS.27 Test")
	void CMS_Test_27 (String oid, TestReporter reporter) {
    	try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
			if (signingCert == null) {
				Exception e = new Exception("Signing Certificate is null");
				throw e;
			}
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("signers is null");
				throw e;
			}
	
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
	
				SignerId signerId = signer.getSID();
				if (signerId.getSerialNumber() == null) {
					Exception e = new Exception("signerId.getSerialNumber() is null");
					throw e;
				}
				//Confirm serial from the cert matched serial from signer info
				assertTrue(signingCert.getSerialNumber().compareTo(signerId.getSerialNumber()) == 0);
			}
    	}
    	catch (Exception e) {
    		fail(e);
    	}
	}
    
	// Validate that signed attribute pivSigner-DN matches the one asserted in signing certificate (split from CMS.12)
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	@DisplayName("CMS.28 Test")
	void CMS_Test_28 (String oid, TestReporter reporter) {
    	try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			X509Certificate signingCert = ((CardHolderUniqueIdentifier) o).getSigningCertificate();
			if (signingCert == null) {
				Exception e = new Exception("Signing Certificate is null");
				throw e;
			}
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("signers is null");
				throw e;
			}
	
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
	
				SignerId signerId = signer.getSID();
				if (signerId == null) {
					Exception e = new Exception("signerId is null");
					throw e;
				}
				AttributeTable attributeTable = signer.getSignedAttributes();
				if (attributeTable == null) {
					Exception e = new Exception("attributeTable is null");
					throw e;
				}
				
				ASN1ObjectIdentifier pivSigner_DN = new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
				Attribute attr = attributeTable.get(pivSigner_DN);
				if (attr == null) {
					Exception e = new Exception("attr is null");
					throw e;
				}
						
				try {
					Principal subjectFromCert = signingCert.getSubjectX500Principal();
					Principal dnFromAttribute = new X500Principal(attr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded());
					
					//Confirm issuer from the cert matcher issuer from the signer info	
					assertTrue(subjectFromCert.equals(dnFromAttribute));
					
				} catch (IOException e) {
					fail(e);
				}
			}
    	}
    	catch (Exception e) {
    		fail(e);
    	}
    	
	}
    
	// Confirm that signed attribute pivFASC-N matches FASC-N read from CHUID container (split from CMS.17)
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	@DisplayName("CMS.29 test")
    //@MethodSource("CMS_TestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_29(String oid, List<String> oidList, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			byte[] fascn = ((CardHolderUniqueIdentifier) o).getfASCN();
			if (fascn == null) {
				Exception e = new Exception("fascn is null");
				throw e;
			}
			byte[] guid = ((CardHolderUniqueIdentifier) o).getgUID();
			
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("signers is null");
				throw e;
			}
	
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
	
				SignerId signerId = signer.getSID();
				if (signerId == null) {
					Exception e = new Exception("signerId is null");
					throw e;
				}
				AttributeTable attributeTable = signer.getSignedAttributes();
				if (attributeTable == null) {
					Exception e = new Exception("attributeTable is null");
					throw e;
				}
				
				Iterator<String> iterator = oidList.iterator();
				while (iterator.hasNext()) {
					String attrOid = iterator.next();
					ASN1ObjectIdentifier pivFASCN_OID = new ASN1ObjectIdentifier(attrOid);
					Attribute attr = attributeTable.get(pivFASCN_OID);
				
					//XXX Need to revisit this test to figure out why is it failing.
					if (attr == null) {
						Exception e = new Exception("attr is null");
						throw e;
					}
					if(attrOid.compareTo("2.16.840.1.101.3.6.6") == 0) {
	
						try {
			
							byte[] fascnEncoded = attr.getEncoded();
							//Confirm issuer from the cert matcher issuer from the signer info	
							assertTrue(Arrays.equals(fascn, fascnEncoded));
							
						} catch (IOException e) {
							throw e;
						}
					}
				}
			}
		}
		catch (Exception e) {
			fail(e);
		}
	}
    
	// Confirm that signed attribute entryUUID matches GUID read from CHUID container (split form CMS.17)
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
	@DisplayName("CMS.30 Test")
	void CMS_Test_30 (String oid, List<String> oidList, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
			CMSSignedData issuerAsymmetricSignature = ((CardHolderUniqueIdentifier) o).getIssuerAsymmetricSignature();
			if (issuerAsymmetricSignature == null) {
				Exception e = new Exception("Issuer Asymmetric Signature is null");
				throw e;
			}
			byte[] fascn = ((CardHolderUniqueIdentifier) o).getfASCN();
			if (fascn == null) {
				Exception e = new Exception("fascn is null");
				throw e;
			}
			byte[] guid = ((CardHolderUniqueIdentifier) o).getgUID();
			
			SignerInformationStore signers = issuerAsymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("signers is null");
				throw e;
			}
	
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
	
				SignerId signerId = signer.getSID();
				if (signerId == null) {
					Exception e = new Exception("signerId is null");
					throw e;
				}
				AttributeTable attributeTable = signer.getSignedAttributes();
				if (attributeTable == null) {
					Exception e = new Exception("attributeTable is null");
					throw e;
				}
				
				Iterator<String> iterator = oidList.iterator();
				while (iterator.hasNext()) {
					String attrOid = iterator.next();
					ASN1ObjectIdentifier pivFASCN_OID = new ASN1ObjectIdentifier(attrOid);
					Attribute attr = attributeTable.get(pivFASCN_OID);
				
					//XXX Need to revisit this test to figure out why is it failing.
					if (attr == null) {
						Exception e = new Exception("attr is null");
						throw e;
					}
					if(attrOid.compareTo("1.3.6.1.1.16.4") == 0) {
						try {
							byte[] guidEncoded = attr.getEncoded();
							//Confirm issuer from the cert matcher issuer from the signer info	
							assertTrue(Arrays.equals(guid, guidEncoded));
						} catch (IOException e) {
							throw e;
						}
					}
				}
			}
		}
		catch (Exception e) {
			fail(e);
		}
	}
    
	@SuppressWarnings("unused")
	private static Stream<Arguments> CMS_TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> CMS_TestProvider2() {

		List<String> oids = Arrays.asList("2.16.840.1.101.3.6.6", "1.3.6.1.1.16.4");
		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,oids));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> CMS_SecurityObjectTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.SECURITY_OBJECT_OID));

	}

}
