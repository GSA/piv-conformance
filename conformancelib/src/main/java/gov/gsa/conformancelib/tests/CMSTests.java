package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.operator.*;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
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
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_1(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		//Confirm that no encapsulated content present
		assertTrue(asymmetricSignature.isDetachedSignature());
    }
	
	//Verify that version is set to 3
	@DisplayName("CMS.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_2(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		//Confirm version is 3
		assertTrue(asymmetricSignature.getVersion() == 3);
    }
	
	//Validate signing key length
	@DisplayName("CMS.3 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_3(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;		
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);

		PublicKey pubKey = signingCert.getPublicKey();
		
		if(pubKey instanceof RSAPublicKey) {
			RSAPublicKey pk = (RSAPublicKey) pubKey;
			assertTrue(pk.getModulus().bitLength() == 2048); // TODO: This assumes only RSA 2048 is used for content signing
		} 
		
		if(pubKey instanceof ECPublicKey) {
			
			// TODO: Add support for P-384 and loop through both curves.  Model for permanent fix for 78-4.{1,2,3}
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
	        // TODO: Support P-384
	        assertTrue(supportedCurve.compareTo(curveFromCert) == 0);
		}
    }

	//Verify digestAlgorithms attribute is present
	@DisplayName("CMS.4 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_4(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(asymmetricSignature);
		assertNotNull(asymmetricSignature.getDigestAlgorithmIDs());
    }
	
	//Ensure encapsulated content is absent
	@DisplayName("CMS.5 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_TestProvider")
	
    void CMS_Test_5(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		try {
			PIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

			//Confirm encapsulated content is absent
			
			assertTrue(asymmetricSignature.getSignedContent() == null, "encapsulated content is NOT absent");
			
			String contentType = asymmetricSignature.getSignedContentTypeOID();
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
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_6(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		
		//Confirm encapsulated content is absent
		assertTrue(asymmetricSignature.isDetachedSignature());
		
		Store<?> crlStore = asymmetricSignature.getCRLs();
		
		Collection<?> crlColl = crlStore.getMatches(null);
		
		assertTrue(crlColl.size() == 0);
    }
	
	//Verify SignerInfos contains only a single signerInfo
	@DisplayName("CMS.7 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_7(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
	
		SignerInformationStore signers = asymmetricSignature.getSignerInfos();
		
		assertNotNull(signers);
		
		//Confirm only one signer is present
		assertTrue(signers.size() == 1);
    }
	
	//Ensure that the signerId uses ths IssuerAndSerialNumber choice
	@DisplayName("CMS.8 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_8(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		SignerInformationStore signers = asymmetricSignature.getSignerInfos();
		
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
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_9(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
    	try {
    		PIVDataObject o = null;
    		CMSSignedData asymmetricSignature = null;
    		o = AtomHelper.getDataObject(oid);
    		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
    		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    		// Underlying decoder for OID identified containers with embedded content signing certs
    		// Now, select the appropriate signature cert for the object
    		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
    		assertNotNull(signingCert, "No signing cert found for OID " + oid);
    		
			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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
	//Verify that the asymmetric digital field contains a CMS signed data object
	@DisplayName("CMS.10 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_10(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    }
		
	// TODO: CMS.11 should digest the content and compare against message digest in signed attributes 

	@DisplayName("CMS.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_11(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		try {
			PIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

			byte[] signedAttrsDigest = ((PIVDataObject) o).getSignedAttrsDigest();
			byte[] computedDigest = ((PIVDataObject) o).getComputedDigest();
			assertTrue(Arrays.equals(signedAttrsDigest, computedDigest));

		} catch (Exception e) {
			fail(e);
		}
	}	

	//Validate that signed attributes includes pivSigner-DN 
	@DisplayName("CMS.12 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_12(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
    	try {
    		PIVDataObject o = null;
    		CMSSignedData asymmetricSignature = null;
    		o = AtomHelper.getDataObject(oid);
    		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
    		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    		// Underlying decoder for OID identified containers with embedded content signing certs
    		// Now, select the appropriate signature cert for the object
    		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
    		assertNotNull(signingCert, "No signing cert found for OID " + oid);

    		SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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
	

	// Verify permissibility of signature algorithm relative to sunset date
	@DisplayName("CMS.13 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_13(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		if (oid.compareTo(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID) == 0 ||
			oid.compareTo(APDUConstants.SECURITY_OBJECT_OID) ==  0) {
			o = AtomHelper.getDataObject(oid);
		}
		else { 
			if (oid.compareTo(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID) == 0 ||
				oid.compareTo(APDUConstants.SECURITY_OBJECT_OID) ==  0 ||
				oid.compareTo(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID) ==  0) {
				o = AtomHelper.getDataObject(oid);
			} else { 
				o = AtomHelper.getDataObject(oid);
			}
		}
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		SignerInformationStore signers = asymmetricSignature.getSignerInfos();
		
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
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_14(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);

        if (o instanceof CardholderBiometricData) {
    		assertTrue(((CardholderBiometricData) o).verifySignature(signingCert));
        } else if (o instanceof SecurityObject) {
    		assertTrue(((SecurityObject) o).verifySignature(signingCert));
        } else 
        	assertTrue(((CardHolderUniqueIdentifier) o).verifySignature());
    }
	
	//Confirm that signing certificate contains id-PIV-content-signing (or PIV-I directly asserted equivalent) in EKU extension
	@DisplayName("CMS.15 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_15(String oid, String params, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		String[] oidList = params.split(",");

		PIVDataObject o = null;
		o = AtomHelper.getDataObject(oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No cert found for OID " + oid);
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(signingCert);

		List<String> ekuList = new ArrayList<String>();
		try {
			ekuList = signingCert.getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			fail(e);
		}
		// Ensure every OID on oidList is in the signed attributes

		for (int i = 0; i < oidList.length; i++) {
			assertTrue(ekuList.contains(oidList[i]));
		}
    }

	//Confirm that signed attributes include pivFASC-N attribute and that it matches FACSC-N read from CHUID container
	@DisplayName("CMS.17 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_TestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_17(String oid, String params, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		try {
			String[] oidList = params.split(",");
			PIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content signing certs
			// Now, select the appropriate signature cert for the object
			X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
			assertNotNull(signingCert, "No signing cert found for OID " + oid);
			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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
				AttributeTable cmsAttributeTable = signer.getSignedAttributes();
				if (cmsAttributeTable == null) {
					ConformanceTestException e = new ConformanceTestException("attributeTable is null");
					throw e;
				}

				// Ensure every OID on oidList is in the signed attributes

				for (int i = 0; i < oidList.length; i++) {
					String requiredAttrOid = oidList[i];
					ASN1ObjectIdentifier currReqAttrOid = new ASN1ObjectIdentifier(requiredAttrOid);
					Attribute reqAttr = cmsAttributeTable.get(currReqAttrOid);
					assertNotNull(reqAttr, "CMS is missing OID " + oidList[i]);
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
    //@MethodSource("CMS_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_18(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);
		
		CMSSignedData signedData = ((SecurityObject) o).getSignedData();

		assertTrue(signedData.getVersion() == 3);
		
    }
	
	//Verify that eContent contains a security object
	@DisplayName("CMS.19 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_19(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);
		
		//Confirm encapsulated content is present
		CMSProcessableByteArray cpb = (CMSProcessableByteArray) asymmetricSignature.getSignedContent();
		byte[] signedContent = (byte[]) cpb.getContent();
		assertNotNull(signedContent);
		assertTrue(signedContent.length > 0);
    }
	
	//Verify that eContentType is id-icao-ldsSecurityObject "1.3.27.1.1.1"
	@DisplayName("CMS.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_20(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);
		
		CMSTypedData ct = asymmetricSignature.getSignedContent();
		
		assertTrue(ct.getContentType().toString().compareTo("1.3.27.1.1.1") == 0);
    }
	
	//Confirm certificates field is omitted
	@DisplayName("CMS.21 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
    //@MethodSource("CMS_TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_21(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);
		
		Store<X509CertificateHolder> certBag = asymmetricSignature.getCertificates();
		
		assertNotNull(certBag);
		assertTrue(certBag.getMatches(null).size() == 0);
    }
	
	//Confirm certificate used to sign CHUID verifies signature
	@DisplayName("CMS.22 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_22(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);
		
		//Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature field and creates CMSSignedData object
		assertNotNull(signingCert);		
		assertTrue(((SecurityObject) o).verifySignature(signingCert));
    }
	
	//Validate signing and digest algorithms
	@DisplayName("CMS.23 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_23(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		PIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);
		
		SignerInformationStore signers = asymmetricSignature.getSignerInfos();
		
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
	@DisplayName("CMS.24 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_24 (String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		
    	try {
    		PIVDataObject o = null;
    		CMSSignedData asymmetricSignature = null;
    		o = AtomHelper.getDataObject(oid);
    		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
    		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    		// Underlying decoder for OID identified containers with embedded content signing certs
    		// Now, select the appropriate signature cert for the object
    		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
    		assertNotNull(signingCert, "No signing cert found for OID " + oid);
    		
			Set<AlgorithmIdentifier> digestAlgSet = asymmetricSignature.getDigestAlgorithmIDs();
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
	@DisplayName("CMS.25 Test")
    //@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_25 (String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;
		try {
    		PIVDataObject o = null;
    		CMSSignedData asymmetricSignature = null;
    		o = AtomHelper.getDataObject(oid);
    		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
    		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    		// Underlying decoder for OID identified containers with embedded content signing certs
    		// Now, select the appropriate signature cert for the object
    		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
    		assertNotNull(signingCert, "No signing cert found for OID " + oid);
				
			Set<AlgorithmIdentifier> digestAlgSet = asymmetricSignature.getDigestAlgorithmIDs();
			if (digestAlgSet == null) {
				Exception e = new Exception("digestAlgSet is null");
				throw e;
			}
			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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
	@DisplayName("CMS.26 Test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    // @MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_26 (String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		try {
    		PIVDataObject o = null;
    		CMSSignedData asymmetricSignature = null;
    		o = AtomHelper.getDataObject(oid);
    		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
    		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    		// Underlying decoder for OID identified containers with embedded content signing certs
    		// Now, select the appropriate signature cert for the object
    		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
    		assertNotNull(signingCert, "No signing cert found for OID " + oid);
    		
			//Confirm encapsulated content is absent
			if (asymmetricSignature.isDetachedSignature() == false) {
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
			assertTrue(ct.getId().compareTo("2.16.840.1.101.3.6.1") == 0);
    	}
    	catch (Exception e) {
    		fail(e);
    	}
	}

	// Ensure that the Serial in the signer info corresponds to the serial value in the signer certificate (split from CMS.9)
	@DisplayName("CMS.27 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_27 (String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		try {
    		PIVDataObject o = null;
    		CMSSignedData asymmetricSignature = null;
    		o = AtomHelper.getDataObject(oid);
    		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    		// Underlying decoder for OID identified containers with embedded content signing certs
    		// Now, select the appropriate signature cert for the object
    		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
    		assertNotNull(signingCert, "No signing cert found for OID " + oid);
			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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
	@DisplayName("CMS.28 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_28 (String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		try {
    		PIVDataObject o = null;
    		CMSSignedData asymmetricSignature = null;
    		o = AtomHelper.getDataObject(oid);
    		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
    		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
    		// Underlying decoder for OID identified containers with embedded content signing certs
    		// Now, select the appropriate signature cert for the object
    		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
    		assertNotNull(signingCert, "No signing cert found for OID " + oid);
    		
			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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
	@DisplayName("CMS.29 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("CMS_SecurityObjectTestProvider")
    //@MethodSource("CMS_TestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void CMS_Test_29(String oid, List<String> oidList, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		try {
			PIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content signing certs
			// Now, select the appropriate signature cert for the object
			X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
			assertNotNull(signingCert, "No signing cert found for OID " + oid);
			
			byte[] fascn = ((CardHolderUniqueIdentifier) o).getfASCN();
			if (fascn == null) {
				Exception e = new Exception("fascn is null");
				throw e;
			}
			((CardHolderUniqueIdentifier) o).getgUID();
			
			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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
	@DisplayName("CMS.30 Test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_30 (String oid, List<String> oidList, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		try {
			PIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content signing certs
			// Now, select the appropriate signature cert for the object
			X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
			assertNotNull(signingCert, "No signing cert found for OID " + oid);
			
			byte[] fascn = ((CardHolderUniqueIdentifier) o).getfASCN();
			if (fascn == null) {
				Exception e = new Exception("fascn is null");
				throw e;
			}
			byte[] guid = ((CardHolderUniqueIdentifier) o).getgUID();
			
			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
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

	
	private static Stream<Arguments> CMS_TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> CMS_TestProvider2() {

		List<String> oids = Arrays.asList("2.16.840.1.101.3.6.6", "1.3.6.1.1.16.4");
		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID,oids));

	}
	
	private static Stream<Arguments> CMS_SecurityObjectTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.SECURITY_OBJECT_OID));

	}

}
