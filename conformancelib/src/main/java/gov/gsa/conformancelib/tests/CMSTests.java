package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.ParameterUtils;
import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.Algorithm;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.SignedPIVDataObject;

public class CMSTests {
	static Logger s_logger = LoggerFactory.getLogger(CMSTests.class);

	// Verify that the asymmetric digital field contains a CMS signed data object
	// with no encapsulated content
	@DisplayName("CMS.1 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_1(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		// Confirm that no encapsulated content present
		assertTrue(asymmetricSignature.isDetachedSignature(), "Signature is not detached as specified");
	}

	// Verify that version is set to 3
	@DisplayName("CMS.2 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_2(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		// Confirm version is 3
		assertTrue(asymmetricSignature.getVersion() == 3, "Version was " + asymmetricSignature.getVersion());
	}

	// The digestAlgorithms field value of the SignedData is in accordance with Table 3-2 of SP 800-78.
	@DisplayName("CMS.3 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_3(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		// CMS digest algorithm must be in Table 3-2, period.
		
		Iterator<AlgorithmIdentifier> ih = asymmetricSignature.getDigestAlgorithmIDs().iterator();	
		while (ih.hasNext()) {
			AlgorithmIdentifier ai = ih.next();
			String digAlgOid = ai.getAlgorithm().getId();
			assertTrue(Algorithm.digAlgOidToNameMap.containsKey(digAlgOid), digAlgOid + " is not in Table 3-2 of SP 800-78-4");
		}		
	}

	// Verify digestAlgorithms attribute is present
	@DisplayName("CMS.4 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_4(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		// Decode for CardHolderUniqueIdentifier reads in Issuer Asymmetric Signature
		// field and creates CMSSignedData object

		assertNotNull(asymmetricSignature.getDigestAlgorithmIDs(), "Digest algorithms are not present in CMS");
	}

	// Ensure Security Object's encapsulated content is absent
	@DisplayName("CMS.5 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider3")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_5(String oid, String params, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		
		try {
			Map<String, List<String>> mp = ParameterUtils.MapFromString(params);
			assertNotNull(mp);
			Iterator<Map.Entry<String,List<String>>> it = mp.entrySet().iterator();
			boolean foundContainer = false;
		    while (it.hasNext()) {
		    	Map.Entry<String,List<String>> pair = it.next();	    	
		        String containerName = pair.getKey();
		        if (containerName.compareTo(APDUConstants.containerOidToNameMap.get(oid)) == 0) {
		        	foundContainer = true;
		        	List<String> pivContentTypeOid = pair.getValue(); // Should only be one item per list

		        	SignedPIVDataObject o = null;
					CMSSignedData asymmetricSignature = null;
					o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
					asymmetricSignature = AtomHelper.getSignedDataForObject(o);
					assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		
					// Confirm encapsulated content is absent
		
					assertTrue(asymmetricSignature.getSignedContent() == null, "encapsulated content is NOT absent");
		
					String contentType = asymmetricSignature.getSignedContentTypeOID();
					// Confirm that content type is id-PIV-CHUIDSecurityObject
					assertTrue(contentType.compareTo(pivContentTypeOid.get(0)) == 0,
							"eContentType is NOT " + pivContentTypeOid.get(0));
					break;
		        }
		    }
			if (!foundContainer) {
				String msg = "Invalid container specified in parameter for this test case";
				s_logger.error(msg);
			}
		} catch (Exception e) {
			fail(e);
		}
	}

	// Ensure CRLs field is absent in signed data structure
	@DisplayName("CMS.6 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_6(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		// Confirm encapsulated content is absent
		assertTrue(asymmetricSignature.isDetachedSignature());

		Store<?> crlStore = asymmetricSignature.getCRLs();

		Collection<?> crlColl = crlStore.getMatches(null);

		assertTrue(crlColl.size() == 0, "CRL file is present");
	}

	// Verify SignerInfos contains only a single signerInfo
	@DisplayName("CMS.7 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_7(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		SignerInformationStore signers = asymmetricSignature.getSignerInfos();

		assertNotNull(signers);

		// Confirm only one signer is present
		assertTrue(signers.size() == 1, "Number of signers is not 1 (one)");
	}

	// Ensure that the signerId uses ths IssuerAndSerialNumber choice
	@DisplayName("CMS.8 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_8(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		SignerInformationStore signers = asymmetricSignature.getSignerInfos();

		assertNotNull(signers);

		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			SignerId signerId = signer.getSID();

			// Confirm issuer and serial number are present
			assertNotNull(signerId.getIssuer());
			assertNotNull(signerId.getSerialNumber());

			// Confirm SKID is absent
			assertTrue(signerId.getSubjectKeyIdentifier() == null, "SKID is present");
		}
	}

	// Ensure that the Issuer in the signer info corresponds to the issuer value in
	// the signer's certificate
	@DisplayName("CMS.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_9(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
			// Now, select the appropriate signature cert for the object
			X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
			assertNotNull(signingCert, "No signing cert found for OID " + oid);

			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("Signers is null");
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
				X500Name tmp1 = new X500Name(issuerFromCert.getName());
				X500Name tmp2 = signerId.getIssuer();
				X500NameStyle style = RFC4519Style.INSTANCE;
				// Confirm issuer from the cert matcher issuer from the signer info
				assertTrue(style.areEqual(tmp1, tmp2),
					"Issuer is not the same as issuer on signing cert");
			}
		} catch (Exception e) {
			fail(e);
		}
	}

	// Verify that the asymmetric digital field contains a CMS signed data object
	@DisplayName("CMS.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_10(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
	}

	// Message digest from signed attributes bag matches the digest over the signed content
	@DisplayName("CMS.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_11(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

			byte[] signedAttrsDigest = o.getSignedAttrsDigest();
			byte[] computedDigest = o.getComputedDigest();
			assertTrue(Arrays.equals(signedAttrsDigest, computedDigest), "Digests don't match");

		} catch (Exception e) {
			fail(e);
		}
	}

	// Validate that signed attributes includes pivSigner-DN
	@DisplayName("CMS.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_12(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
			// Now, select the appropriate signature cert for the object
			X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
			assertNotNull(signingCert, "No signing cert found for OID " + oid);

			SignerInformationStore signers = asymmetricSignature.getSignerInfos();
			if (signers == null) {
				Exception e = new Exception("Signers is null");
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
					Exception e = new Exception("AttributeTable is null");
					throw e;
				}

				ASN1ObjectIdentifier pivSigner_DN = new ASN1ObjectIdentifier("2.16.840.1.101.3.6.5");
				Attribute attr = attributeTable.get(pivSigner_DN);
				assertNotNull(attr, "Missing pivSigner-DN");
			}
		} catch (Exception e) {
			fail(e);
		}
	}

	// Verify permissibility of signature algorithm relative to sunset date
	@DisplayName("CMS.13 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_13(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		SignerInformationStore signers = asymmetricSignature.getSignerInfos();

		assertNotNull(signers);

		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			assertTrue(Algorithm.digAlgOidToNameMap.containsKey(
				signer.getDigestAlgOID()), "Digest algorithm list does not contain" + signer.getDigestAlgOID());
			if (it.hasNext()) {
				s_logger.warn("More than one signer");
			}
		}
	}

	// Confirm that the certificate from the cert bag successfully validates the CMS
	// signature
	@DisplayName("CMS.14 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_14(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid)) return;

		SignedPIVDataObject o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		assertNotNull(AtomHelper.getSignedDataForObject(o), "No signature found for OID " + oid);
		assertTrue(o.verifySignature(), "Object signature does not verify");
	}

	// Confirm that signing certificate contains id-PIV-content-signing (or PIV-I
	// directly asserted equivalent) in EKU extension
	@DisplayName("CMS.15 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_15(String oid, String params, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		String[] oidList = params.split(",");

		SignedPIVDataObject o = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No cert found for OID " + oid);

		List<String> ekuList = new ArrayList<String>();
		try {
			ekuList = signingCert.getExtendedKeyUsage();
		} catch (CertificateParsingException e) {
			fail(e);
		}
		// Ensure every OID on oidList is in the signed attributes

		for (int i = 0; i < oidList.length; i++) {
			assertTrue(ekuList.contains(oidList[i]), "Certificate does not contain" + oidList[i]);
		}
	}

	// Confirm that signed attributes include pivFASC-N attribute and that it
	// matches FASC-N read from CHUID container
	@DisplayName("CMS.17 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_17(String oid, String params, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		try {
			String[] oidList = params.split(",");
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
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
		} catch (Exception e) {
			fail(e);
		}
	}

	// Confirm that version of signed data structure is 1
	@DisplayName("CMS.18 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_18(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content
		// signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);
		CMSSignedData signedData = o.getAsymmetricSignature();
		assertTrue(signedData.getVersion() == 3, "CMSSignedData version is not 3 (three)");
	}

	// Verify that eContent contains a security object
	@DisplayName("CMS.19 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_19(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content
		// signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);

		// Confirm encapsulated content is present
		CMSProcessableByteArray cpb = (CMSProcessableByteArray) asymmetricSignature.getSignedContent();
		byte[] signedContent = (byte[]) cpb.getContent();
		assertNotNull(signedContent);
		assertTrue(signedContent.length > 0, "Does not appear to contain a Security Object");
	}

	// Verify that eContentType is id-icao-ldsSecurityObject "1.3.27.1.1.1"
	@DisplayName("CMS.20 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_20(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content
		// signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);

		CMSTypedData ct = asymmetricSignature.getSignedContent();

		assertTrue(ct.getContentType().toString().compareTo("1.3.27.1.1.1") == 0,
				"Content type is not id-icao-ldsSecurityObject");
	}

	// Confirm certificates field is omitted
	@DisplayName("CMS.21 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_21(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		// Underlying decoder for OID identified containers with embedded content
		// signing certs
		// Now, select the appropriate signature cert for the object
		X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
		assertNotNull(signingCert, "No signing cert found for OID " + oid);

		Store<X509CertificateHolder> certBag = asymmetricSignature.getCertificates();

		assertNotNull(certBag);
		assertTrue(certBag.getMatches(null).size() == 0, "Certificate(s) are present and shouldn't");
	}

	// Validate signing and digest algorithms
	/*
	 * 
	 * Table 3-2. Signature Algorithm and Key Size Requirements for PIV Information
	 * Public Key Algorithms and Key Sizes | Hash Algorithms | Padding Scheme
	 * RSA (2048 or 3072)                  | SHA-256         | PKCS #1 v1.5
	 *                                     | SHA-256         | PSS
	 * ------------------------------------+-----------------+-----------------
	 * ECDSA (Curve P-256)                 | SHA-256         | N/A
	 * ECDSA (Curve P-384)                 | SHA-384         | N/A
	 * 
	 * Note: As of January 1, 2011, only SHA-256 may be used to generate RSA
	 * signatures on PIV objects. RSA signatures may use either the PKCS #1 v1.5
	 * padding scheme or the Probabilistic Signature Scheme (PSS) padding as defined
	 * in [PKCS1]. The PSS padding scheme object identifier (OID) is independent of
	 * the hash algorithm; the hash algorithm is specified as a parameter (for
	 * details, see [PKCS1]). 
	 * 
	 * The secure messaging CVC shall be signed using ECDSA
	 * (Curve P-256) with SHA-256 if it contains an ECDH (Curve P-256) subject
	 * public key, and shall be signed using ECDSA (Curve P-384) with SHA-384
	 * otherwise. The Intermediate CVC shall be signed using RSA with SHA-256 and
	 * PKCS #1 v1.5 padding. 
	 * 
	 * FIPS 201-2, SP 800-73-4, and SP 800-76-2 specify
	 * formats for the CHUID, the Security Object, the biometric information, and
	 * X.509 public key certificates, which rely on OIDs to specify which signature
	 * algorithm was used to generate the digital signature. The object identifiers
	 * specified in Table 3-3, below, must be used in FIPS 201-2 implementations to
	 * identify the signature algorithm. 4,5
	 * 
	 * For the CHUID, Security Object, and biometric information the
	 * signatureAlgorithm field of SignerInfo shall contain rsaEncryption
	 * (1.2.840.113549.1.1.1) when the signature algorithm is RSA wit PKCS #1 v1.5
	 * padding.
	 * 
	 * 3.2.3: SP 800-73-4 mandates inclusion of a Security Object consistent with
	 * the Authenticity/Integrity Code defined by the International Civil Aviation
	 * Organization (ICAO) in [MRTD]. This object contains message digests of other
	 * digital information stored on the PIV Card and is digitally signed. This
	 * specification requires that the message digests of digital information be
	 * computed using the same hash algorithm used to generate the digital signature
	 * on the Security Object. The set of acceptable algorithms is specified in
	 * Table 3-2. The Security Object format identifies the hash algorithm used when
	 * computing the message digests by inclusion of an object identifier; the
	 * appropriate object identifiers are identified in Table 3-6. 6
	 * 
	 * Hash Algorithm  | Object Identifier (OID)
	 *-----------------+-----------------
	 * SHA-256         | 2.16.840.1.101.3.4.2.1
	 * SHA-384         | 2.16.840.1.101.3.4.2.2
	 */
	@DisplayName("CMS.23 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_23(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
		assertTrue(Algorithm.isDigestAlgInTable32(asymmetricSignature), "Unsupported digest algorithm");

		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));

		int keylen = 0;
		PublicKey pk = cert.getPublicKey();
		if (pk instanceof BCRSAPublicKey) {
			BCRSAPublicKey rsaPk = (BCRSAPublicKey) pk;
			keylen = rsaPk.getModulus().bitLength();
			assertTrue((keylen == 2048 || keylen == 3072), keylen + " is an invalid key length");
		} else if (pk.getClass().toString().contains("EC")) {
			ECPublicKey ec = (ECPublicKey) pk;
			keylen = ec.getParams().getCurve().getField().getFieldSize();
			assertTrue((keylen == 256 || keylen == 384), keylen + " is an invalid key length");
		}
		s_logger.debug("Public key length: {}", keylen);
		
		// Key length is valid, so compare the digest algorithm of the signature with the
		// list of supported algorithms.
		
		HashSet<String> dalgList = new HashSet<String>();
		
		Iterator<AlgorithmIdentifier> ih = asymmetricSignature.getDigestAlgorithmIDs().iterator();	
		while (ih.hasNext()) {
			AlgorithmIdentifier ai = ih.next();
			dalgList.add(ai.getAlgorithm().getId());
		}
		
		SignerInformationStore signers = null;

		signers = asymmetricSignature.getSignerInfos();
		assertTrue((signers != null), "Signers is null");
		
		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			String digAlgOid = signer.getDigestAlgorithmID().getAlgorithm().getId();
			assertTrue(dalgList.contains(digAlgOid), digAlgOid + " is not a supported digest algorithm");
		}
	}	

	// Verify digest algorithm is present (extended from CMS.4)
	@DisplayName("CMS.24 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_24(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
			// Now, select the appropriate signature cert for the object
			X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
			assertNotNull(signingCert, "No signing cert found for OID " + oid);

			Set<AlgorithmIdentifier> digestAlgSet = asymmetricSignature.getDigestAlgorithmIDs();
			if (digestAlgSet == null) {
				Exception e = new Exception("digestAlgSet is null");
				throw e;
			}
			// Confirm that digestAlgorithms attribute is present and algorithm is present
			assertTrue(digestAlgSet.size() > 0);
		} catch (Exception e) {
			fail(e);
		}
	}

	// Verify that digest algorithm is consistent with the signature algorithm
	// (split from CMS.4)
	@ParameterizedTest(name = "{index} => oid = {0}")
	@DisplayName("CMS.25 Test")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_25(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
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
				assertTrue(digestAlgSet.contains(algID), "Digest algorithm " + algID.toString() + " is unspported in PIV");
			}
		} catch (Exception e) {
			fail(e);
		}
	}

	// Ensure eContentType is id-piv-CHUIDSecurityContent in encapContentInfo (split
	// from CMS.5)
	@DisplayName("CMS.26 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_26(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
			// Now, select the appropriate signature cert for the object
			X509Certificate signingCert = AtomHelper.getCertificateForContainer(o);
			assertNotNull(signingCert, "No signing cert found for OID " + oid);

			// Confirm encapsulated content is absent
			if (asymmetricSignature.isDetachedSignature() == false) {
				Exception e = new Exception("isDetachedSignature is false");
				throw e;
			}
			ContentInfo contentInfo = o.getContentInfo();
			ASN1Encodable content = contentInfo.getContent();
			// Confirm that encapsulated content is absent
			if (content != null) {
				Exception e = new Exception("Encapsulated content is not null");
				throw e;
			}
			ASN1ObjectIdentifier ct = contentInfo.getContentType();
			assertTrue(ct.getId().compareTo("2.16.840.1.101.3.6.1") == 0, "Couldn't find OID for id-piv-CHUIDSecurityContent");
		} catch (Exception e) {
			fail(e);
		}
	}

	// Ensure that the Serial in the signer info corresponds to the serial value in
	// the signer certificate (split from CMS.9)
	@DisplayName("CMS.27 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_SecurityObjectTestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_27(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
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
				// Confirm serial from the cert matched serial from signer info
				assertTrue(signingCert.getSerialNumber().compareTo(signerId.getSerialNumber()) == 0);
			}
		} catch (Exception e) {
			fail(e);
		}
	}

	// Validate that signed attribute pivSigner-DN matches the one asserted in
	// signing certificate (split from CMS.12)
	@DisplayName("CMS.28 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_28(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		try {
			SignedPIVDataObject o = null;
			CMSSignedData asymmetricSignature = null;
			o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
			asymmetricSignature = AtomHelper.getSignedDataForObject(o);
			assertNotNull(asymmetricSignature, "No signature found for OID " + oid);
			// Underlying decoder for OID identified containers with embedded content
			// signing certs
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
					Principal dnFromAttribute = new X500Principal(
							attr.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded());

					// Confirm issuer from the cert matcher issuer from the signer info
					assertTrue(subjectFromCert.equals(dnFromAttribute), "Issuer from signer info doens't match issuer on signing cert");

				} catch (IOException e) {
					fail(e);
				}
			}
		} catch (Exception e) {
			fail(e);
		}

	}

	// Confirm that signed attribute pivFASC-N matches FASC-N read from CHUID
	// container (split from CMS.17)
	@DisplayName("CMS.29 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_29(String oid, String fascnOID, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		CardHolderUniqueIdentifier o2 = 
				(CardHolderUniqueIdentifier) AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		if (o2 == null) {
			fail("CHUID object is null");
		}
		
		byte[] fascn = o2.getfASCN();
		if (fascn == null) {
			fail("FASC-N in CHUID object is null");
		}

		SignerInformationStore signers = asymmetricSignature.getSignerInfos();
		if (signers == null) {
			fail("Signers is null");
		}

		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			SignerId signerId = signer.getSID();
			assertTrue(signerId != null, "SignerId is null");

			AttributeTable attributeTable = signer.getSignedAttributes();
			assertTrue (attributeTable != null, "AttributeTable is null");

			ASN1ObjectIdentifier pivFASCN_OID = new ASN1ObjectIdentifier(fascnOID);
			Attribute attr = attributeTable.get(pivFASCN_OID);

			assertTrue(attr != null, String.format("Attribute %s not found in signed attributes", fascnOID));

			ASN1Set fascnAttr = attr.getAttrValues();
			assertTrue(fascnAttr != null, String.format("No value for %s attribute", fascnOID));
			assertTrue(fascnAttr.size() == 1, "FASC-N attribute has multiple values");

			try {
				DEROctetString fascnOctetString = (DEROctetString) fascnAttr.getObjectAt(0).toASN1Primitive();
				assertTrue(fascnOctetString != null, "FASC-N in attribute set is null");
				// Confirm that signed attribute pivFASC-N matches FASC-N read from CHUID
				byte[] fe = fascnOctetString.getEncoded();
				assertTrue(Arrays.equals(fascn, Arrays.copyOfRange(fe, 2, fe.length)), "FASC-N mismatch with CHUID");
			} catch (IOException e) {
				fail(e);
			}
		}
	}

	// Confirm that signed attribute entryUUID matches GUID read from CHUID
	// container (split form CMS.17)
	@DisplayName("CMS.30 Test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("CMS_TestProvider3")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void CMS_Test_30(String oid, String uuidOID, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;

		SignedPIVDataObject o = null;
		CMSSignedData asymmetricSignature = null;
		o = (SignedPIVDataObject) AtomHelper.getDataObject(oid);
		asymmetricSignature = AtomHelper.getSignedDataForObject(o);
		assertNotNull(asymmetricSignature, "No signature found for OID " + oid);

		CardHolderUniqueIdentifier o2 = 
				(CardHolderUniqueIdentifier) AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		if (o2 == null) {
			fail("CHUID object is null");
		}
		
		byte[] uuid = o2.getgUID();
		if (uuid == null) {
			fail("UUID in CHUID object is null");
		}

		SignerInformationStore signers = asymmetricSignature.getSignerInfos();
		if (signers == null) {
			fail("Signers is null");
		}

		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();

			SignerId signerId = signer.getSID();
			assertTrue(signerId != null, "SignerId is null");

			AttributeTable attributeTable = signer.getSignedAttributes();
			assertTrue (attributeTable != null, "AttributeTable is null");

			ASN1ObjectIdentifier entryUUID_OID = new ASN1ObjectIdentifier(uuidOID);
			Attribute attr = attributeTable.get(entryUUID_OID);

			assertTrue(attr != null, String.format("Attribute %s not found in signed attributes", uuidOID));

			ASN1Set uuidAttr = attr.getAttrValues();
			assertTrue(uuidAttr != null, String.format("No value for %s attribute", uuidOID));
			assertTrue(uuidAttr.size() == 1, "UUID attribute has multiple values");

			try {
				DEROctetString uuidOctetString = (DEROctetString) uuidAttr.getObjectAt(0).toASN1Primitive();
				assertTrue(uuidOctetString != null, "UUID in attribute set is null");
				// Confirm that signed attribute pivFASC-N matches FASC-N read from CHUID
				byte[] ue = uuidOctetString.getEncoded();
				assertTrue(Arrays.equals(uuid, Arrays.copyOfRange(ue, 2, ue.length)), "FASC-N mismatch with CHUID");
			} catch (IOException e) {
				fail(e);
			}
		}
	}

	private static Stream<Arguments> CMS_TestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID),
				Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID),
				Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID),
				Arguments.of(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID));
	}

	@SuppressWarnings("unused")
	private static Stream<Arguments> CMS_TestProvider2() {

		String oid =  "2.16.840.1.101.3.6.6";
		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, oid),
				Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, oid),
				Arguments.of(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID, oid));
	}
	
	@SuppressWarnings("unused")
	private static Stream<Arguments> CMS_TestProvider3() {

		String oid =  "1.3.6.1.1.16.4";
		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, oid),
				Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, oid),
				Arguments.of(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID, oid));
	}

	private static Stream<Arguments> CMS_SecurityObjectTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.SECURITY_OBJECT_OID));
	}

	private static Stream<Arguments> CMS_SecurityObjectTestProvider2() {

		return Stream.of(Arguments.of(APDUConstants.SECURITY_OBJECT_OID, 
				"CARD_HOLDER_UNIQUE_IDENTIFIER_OID:2.16.840.1.101.3.6.1," +
				"CARDHOLDER_FINGERPRINTS_OID:2.16.840.1.101.3.6.2," + 
				"CARDHOLDER_FACIAL_IMAGE_OID:2.16.840.1.101.3.6.2," + 
				"CARDHOLDER_IRIS_IMAGES_OID:2.16.840"));
	}
	

	private static Stream<Arguments> CMS_SecurityObjectTestProvider3() {

		return Stream.of(Arguments.of(APDUConstants.SECURITY_OBJECT_OID, "2.16.840.1.101.3.6.1"));
	}
}
