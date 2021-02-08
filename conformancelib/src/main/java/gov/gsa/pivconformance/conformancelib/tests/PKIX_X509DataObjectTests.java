package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.cardlib.card.client.*;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterUtils;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class PKIX_X509DataObjectTests {
	private static final Logger s_logger = LoggerFactory.getLogger(PKIX_X509DataObjectTests.class);
	public static final HashMap<String, String> PKIX_X509DataObjectIdentifiers = new HashMap<String, String>() {
		private static final long serialVersionUID = 1L;
		{
			put ("X509_id",  "1.3.6.1.5.5");
			put ("X509_id_pkix",  "1.3.6.1.5.5.7");
			put ("X509_id_pe",  "1.3.6.1.5.5.7.1");
			put ("X509_id_pe_authorityInfoAccess",  "1.3.6.1.5.5.7.1.1");
			put ("X509_id_ad",  "1.3.6.1.5.5.7.48");
			put ("X509_id_ad_ocsp",  "1.3.6.1.5.5.7.48.1");
			put ("X509_id_ad_caIssuers",  "1.3.6.1.5.5.7.48.2");
			put ("X509_id_ce",  "2.5.29");
			put ("X509_id_ce_subjectKeyIdentifier",  "2.5.29.14");
			put ("X509_id_ce_keyUsage",  "2.5.29.15");
			put ("X509_id_ce_subjectAltName",  "2.5.29.17");
			put ("X509_id_ce_issuerAltName",  "2.5.29.18");
			put ("X509_id_ce_cRLDistributionPoints",  "2.5.29.31");
			put ("X509_id_ce_certificatePolicies",  "2.5.29.32");
			put ("X509_id_ce_policyMappings",  "2.5.29.33");
			put ("X509_id_ce_authorityKeyIdentifier",  "2.5.29.35");
			put ("X509_id_ce_extKeyUsage",  "2.5.29.37");
			put ("X509_id_ce_anyExtendedKeyUsage",  "2.5.29.37.0");
			put ("X509_id_ce_basicConstraints",  "2.5.29.19");
			put ("X509_id_ce_nameConstraints",  "2.5.29.30");
			put ("X509_id_ce_policyConstraints",  "2.5.29.36");
			put ("X509_id_ce_inhibitAnyPolicy",  "2.5.29.54");
		}
	};

	/**
	 * Converts a boolean array to a byte array representing the bitmap in high-order first
	 * representation
	 * @param in incoming boolean array representing bits
	 * @return byte array representing the bitmap
	 */
	byte[] bitsToBytes(boolean[] in) {
		byte[] outBytes = new byte[(in.length / 8) + 1];
		int inIdx = 0;
		for (int octetctr = 0; octetctr < outBytes.length; octetctr++) {
			for (int bitctr = 7; inIdx < in.length && bitctr >=0; bitctr--) {
				if (in[inIdx++]) {
					outBytes[octetctr] |= 1 << bitctr;
				}
			}
		}
		return outBytes;
	}

	// Confirm keyUsage extension is present
	@DisplayName("PKIX.2 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_2(String oid, TestReporter reporter) { 
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);

		assertTrue(cert.getKeyUsage() != null, "Key usage extension is absent");
	}

	// Confirm digitalSignature bit is set
	@DisplayName("PKIX.3 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_PIVAuthx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_3(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
	
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
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;		
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean[] foundBits = cert.getKeyUsage();
		assertNotNull(foundBits, "keyUsage extension is absent");
		byte[] foundBytes = bitsToBytes(foundBits);
		KeyUsage foundUsage = KeyUsage.getInstance(new DERBitString(foundBytes, 6));
		// confirm key usage extension is present
		if(foundUsage == null) {
			Exception e = new Exception("key usage is null");
			fail(e);
		}

		if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID) == 0){
			assertTrue(foundUsage.hasUsages(KeyUsage.digitalSignature), "digitialSignature is not set");
			assertFalse(foundUsage.hasUsages(KeyUsage.nonRepudiation), "nonRepudiation is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyAgreement), "keyAgreement is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.dataEncipherment), "dataEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyEncipherment), "keyEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyCertSign), "keyCertSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.cRLSign), "cRLSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.encipherOnly), "encipherOnly");
			assertFalse(foundUsage.hasUsages(KeyUsage.decipherOnly), "decipherOnly");
        } else if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID) == 0){
			assertTrue(foundUsage.hasUsages(KeyUsage.digitalSignature), "digitialSignature is not set");
			assertTrue(foundUsage.hasUsages(KeyUsage.nonRepudiation), "nonRepudiation is not set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyAgreement), "keyAgreement is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.dataEncipherment), "dataEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyEncipherment), "keyEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyCertSign), "keyCertSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.cRLSign), "cRLSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.encipherOnly), "encipherOnly is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.decipherOnly), "decipherOnly is set");
        } else if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID) == 0) {
			if (cert.getPublicKey() instanceof RSAPublicKey) {
				assertFalse(foundUsage.hasUsages(KeyUsage.digitalSignature), "digitialSignature is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.nonRepudiation), "nonRepudiation is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.keyAgreement), "keyAgreement is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.dataEncipherment), "dataEncipherment is set");
				assertTrue(foundUsage.hasUsages(KeyUsage.keyEncipherment), "keyEncipherment is not set");
				assertFalse(foundUsage.hasUsages(KeyUsage.keyCertSign), "keyCertSign is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.cRLSign), "cRLSign is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.encipherOnly), "encipherOnly is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.decipherOnly), "decipherOnly is set");
			} else if (cert.getPublicKey() instanceof ECPublicKey) {
				assertFalse(foundUsage.hasUsages(KeyUsage.digitalSignature), "digitialSignature is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.nonRepudiation), "nonRepudiation is set");
				assertTrue(foundUsage.hasUsages(KeyUsage.keyAgreement), "keyAgreement is not set");
				assertFalse(foundUsage.hasUsages(KeyUsage.dataEncipherment), "dataEncipherment is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.keyEncipherment), "keyEncipherment is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.keyCertSign), "keyCertSign is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.cRLSign), "cRLSign is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.encipherOnly), "encipherOnly is set");
				assertFalse(foundUsage.hasUsages(KeyUsage.decipherOnly), "decipherOnly is set");
			}
        } else if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID) == 0){
			assertTrue(foundUsage.hasUsages(KeyUsage.digitalSignature), "digitialSignature is not set");
			assertFalse(foundUsage.hasUsages(KeyUsage.nonRepudiation), "nonRepudiation is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyAgreement), "keyAgreement is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.dataEncipherment), "dataEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyEncipherment), "keyEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyCertSign), "keyCertSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.cRLSign), "cRLSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.encipherOnly), "encipherOnly");
			assertFalse(foundUsage.hasUsages(KeyUsage.decipherOnly), "decipherOnly");
        } else if(oid.compareTo(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID) == 0){
			assertTrue(foundUsage.hasUsages(KeyUsage.digitalSignature), "digitialSignature is not set");
			assertFalse(foundUsage.hasUsages(KeyUsage.nonRepudiation), "nonRepudiation is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyAgreement), "keyAgreement is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.dataEncipherment), "dataEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyEncipherment), "keyEncipherment is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.keyCertSign), "keyCertSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.cRLSign), "cRLSign is set");
			assertFalse(foundUsage.hasUsages(KeyUsage.encipherOnly), "encipherOnly");
			assertFalse(foundUsage.hasUsages(KeyUsage.decipherOnly), "decipherOnly");
        }
	}

	// Confirm certificate policies extension is present
	@DisplayName("PKIX.5 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_5(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);

		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_ce_certificatePolicies"));
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null, "Certificate policies extension is absent");
    }

 	// Confirm that id- fpki-common-authentication 2.16.840.1.101.3.2.1.3.13 OID (or PIV-I or ICAM Test equivalent)
	// is asserted in certificate policies (parameters required)
	@DisplayName("PKIX.6 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_PIVAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_6(String oid, String containersAndPolicyOids, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate eeCert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(eeCert, "Certificate could not be read for " + oid);

		if (containersAndPolicyOids == null) {
			ConformanceTestException e  = new ConformanceTestException("policyOid is null");
			fail(e);
		}
		String[] containerOidList = containersAndPolicyOids.replaceAll("\\s+", "").split(",");
		
		HashMap<String,List<String>> rv = new HashMap<String,List<String>>();
		String failMsg = null;
		boolean valid = false;
		for(String p : containerOidList) {
			String[] allowedPolicies = p.split(":");
			String policyOidValue = APDUConstants.getStringForFieldNamed(allowedPolicies[0]).trim();
			if (policyOidValue.equals(oid)) {
				String containerOid = allowedPolicies[0].trim();
				s_logger.debug("For {}, one of policy OIDs ({}) should be asserted", containerOid, allowedPolicies[1]);
				try {
					Validator validator = new Validator("SunRsaSign", "cacerts.jks", "changeit");
					s_logger.debug(validator.toString());
					// Validate cert to trust anchor in default keystore
					valid = validator.isValid(eeCert, allowedPolicies[1], null);
					if (valid == true)  {
						s_logger.debug("Certificate is valid");
						s_logger.debug(validator.toString());
						if (validator.getCertPath() != null) {
							validator.dumpCertPath(true);
						} else {
							failMsg = "Certificate is invalid";
							s_logger.error(failMsg);
						}
					}
				} catch (Exception e) {
					failMsg = e.getMessage();
					s_logger.error(failMsg);
				}
			}
		}
		assertTrue(valid, failMsg);
    }
	
	/* ******************* Standard stuff for most all certs ************************ */

	/**
	 * Determines whether the AIA in cert contains the prescribed AccessMethod (id-ad-ocsp or id-ad-caIssuers)
	 * @param aia AIA extension of certificate to be tested
	 * @param accessMethod the AccessDescription corresponding the the AccessMethod
	 * @return true if the AIA in cert contains the prescribed AccessMethod, false otherwise
	 */

	private boolean aiaContainsAccessMethod(AuthorityInformationAccess aia, ASN1ObjectIdentifier accessMethod) {
		try {
			AccessDescription[] descriptions = aia.getAccessDescriptions();
			for (AccessDescription ad : descriptions) {
				if (ad.getAccessMethod().equals(accessMethod)) {
					return true;
				}
			}
		} catch (Exception e) {
			s_logger.error(e.getMessage());
		}

		s_logger.error("Access method " + accessMethod.toString() + " not present");
		return false;
	}

	/**
	 * Determines whether an access location for the specified AIA access method in cert contains
	 * a uniformResourceIdentifier GeneralName (The accessLocation for the id-ad-ocsp AccessMethod
	 * is of type uniformResourceIdentifier)
	 *
	 * @param aia AIA extension from the certificate to be tested
	 * @param accessMethod the AccessDescription corresponding the the AccessMethod
	 * @return true if the URI accessMethod is present, false otherwise
	 */
	private boolean accessMethodContainsURI(AuthorityInformationAccess aia, ASN1ObjectIdentifier accessMethod) {
		try {
			AccessDescription[] descriptions = aia.getAccessDescriptions();
			for (AccessDescription ad : descriptions) {
				if (ad.getAccessMethod().equals(accessMethod)) {
					GeneralName gn = ad.getAccessLocation();
					if (gn.getTagNo() == GeneralName.uniformResourceIdentifier)
						return true;
				}
			}
		} catch (Exception e) {
			s_logger.error(e.getMessage());
		}
		s_logger.error("URI accessMethod " + accessMethod.toString() + " not present");
		return false;
	}

	/**
	 * Confirms the URI scheme in the specified accessLocation for the specified access method is http
	 *
	 * @param aia certificate to be tested
	 * @param accessMethod the AccessDescription corresponding the the AccessMethod
	 * @return true if the URI scheme is "http", false otherwise
	 */
	private boolean aIAUriContainsHttp(AuthorityInformationAccess aia, ASN1ObjectIdentifier accessMethod) {
		try {
			AccessDescription[] descriptions = aia.getAccessDescriptions();
			for (AccessDescription ad : descriptions) {
				if (ad.getAccessMethod().equals(accessMethod)) {
					GeneralName gn = ad.getAccessLocation();
					if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
						String url = ((DERIA5String) gn.getName()).getString();
						if (url.startsWith("http:")) {
							return true;
						}
					}
				}
			}
		} catch (Exception e) {
			s_logger.error(e.getMessage());
		}
		s_logger.error("URI scheme in " + accessMethod.toString() + " is not http");
		return false;
	}

	/**
	 * Determines whether the URI in the CRL Distribution Point contains an URL starting with http:
	 * @param crldp CRL distribution point object
	 * @return true if the URI starts with https:, false otherwise
	 */
	private boolean crldpStartsWithHTTP(CRLDistPoint crldp) {
		try {
			DistributionPoint[] descriptions = crldp.getDistributionPoints();
			for (DistributionPoint dp : descriptions) {
				DistributionPointName dpn = dp.getDistributionPoint();
				if (dpn.getType() == DistributionPointName.FULL_NAME) {
					GeneralName[] generalNames = GeneralNames.getInstance(dpn.getName()).getNames();
					for (GeneralName gn : generalNames) {
						if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
							String url = ((DERIA5String) gn.getName()).getString().toLowerCase();
							if (url.startsWith("http:")) {
								return true;
							}
						}
					}
				}
			}
		} catch (Exception e) {
			s_logger.error(e.getMessage());
		}

		s_logger.error("CRL DP URI does not end in .crl");
		return false;
	}

	/**
	 * Determines whether the URI in the CRL Distribution Point contains an URL ending in .crl
	 * @param crldp distribution point object
	 * @return true if the URI ends in .crl, false otherwise
	 */
	private boolean crldpEndWithCRL(CRLDistPoint crldp) {
		try {
			DistributionPoint[] descriptions = crldp.getDistributionPoints();
			for (DistributionPoint dp : descriptions) {
				DistributionPointName dpn = dp.getDistributionPoint();
				if (dpn.getType() == DistributionPointName.FULL_NAME) {
					GeneralName[] generalNames = GeneralNames.getInstance(dpn.getName()).getNames();
					for (GeneralName gn : generalNames) {
						if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
							String url = ((DERIA5String) gn.getName()).getString().toLowerCase();
							if (url.endsWith(".crl")) {
								return true;
							}
						}
					}
				}
			}
		} catch (Exception e) {
			s_logger.error(e.getMessage());
		}

		s_logger.error("CRL DP URI does not end in .crl");
		return false;
	}

	//Confirm that authorityInformationAccess extension is present
	@DisplayName("PKIX.7 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_7(String oid, TestReporter reporter) {
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));
		
		//Confirm authorityInformationAccess extension is present
		assertTrue(aiaex != null, "AIA extension is not present");
	}

	//An accessMethod containing id-ad-ocsp is present (only PIV auth requires this)
	@DisplayName("PKIX.8 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_8(String oid, TestReporter reporter) {
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));
		
		if (aiaex != null) {
			AuthorityInformationAccess aia = null;
			try {
				aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(aiaex));
				if (aiaContainsAccessMethod(aia, X509ObjectIdentifiers.ocspAccessMethod)) {
					rv = true;
				}
			} catch (Exception e) {
				s_logger.error("AIA decoding failed: " + e.getMessage());
			}
	    } else {
	    	ConformanceTestException e  = new ConformanceTestException("No AIA is present.");
	    }
		assertTrue (rv, "An accessMethod containing " +  X509ObjectIdentifiers.ocspAccessMethod.toString() + " is not present");
	}

	//The accessLocation for the id-ad-ocsp AccessMethod is of type uniformResourceIdentifier.
	@DisplayName("PKIX.9 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_9(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;
		byte[] aiaex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));
		if (aiaex != null) {
			try {
				AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(aiaex));
				if (aiaContainsAccessMethod(aia, X509ObjectIdentifiers.ocspAccessMethod)) {
					if (accessMethodContainsURI(aia, X509ObjectIdentifiers.ocspAccessMethod)) {
						rv = true;
					}
				}
			} catch (Exception e) {
				s_logger.error("Exception decoding AIA", e.getMessage());
			}
		} else {
			s_logger.error("No AIA is present");
		}
		assertTrue (rv, "The accessLocation for this AccessMethod is not of type uniformResourceIdentifier.");
	}

	//Confirm that the access location for OCSP is http protocol
	@DisplayName("PKIX.23 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_23(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;

		byte[] aiaex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));

		if (aiaex != null) {
			try {
				AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(aiaex));
				if (aiaContainsAccessMethod(aia, X509ObjectIdentifiers.ocspAccessMethod)) {
					if (accessMethodContainsURI(aia, X509ObjectIdentifiers.ocspAccessMethod)) {
						if (aIAUriContainsHttp(aia, X509ObjectIdentifiers.ocspAccessMethod)) {
							rv = true;
						}
					}
				}
			} catch (IOException e) {
				fail(e);
			}
		} else {
			ConformanceTestException e  = new ConformanceTestException("No AIA extension present.");
			fail(e);
		}
		assertTrue (rv, "OCSP URL does not start with http:");
    }
	
	//Confirm that piv interim "2.16.840.1.101.3.6.9.1" extension is present
	@DisplayName("PKIX.10 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_PIVAuthx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_10(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;		
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);

		if (cert != null) {
			//Get piv interim "2.16.840.1.101.3.6.9.1" extension
			byte[] pivInterim = cert.getExtensionValue("2.16.840.1.101.3.6.9.1");
			
			//Confirm pivInterim extension is present and isn't empty
			assertTrue(pivInterim != null, "pivInterim extension is not present");
			assertTrue(pivInterim.length > 0, "pivInterim extension is empty");
		}
    }
	
	//Sign arbitrary data using the specified key container and confirm that the certificate can validate it
	@DisplayName("PKIX.11 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_11(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);

		// issue #107... temporarily turning red all the time to avoid repeat
		//ConformanceTestException e = new ConformanceTestException("PKIX.11 needs to always fail until 107 is addressed.");
		//fail(e);
		KeyValidationHelper kvh = KeyValidationHelper.getInstance();
		try {
			kvh.validateKey(cert, oid);
			s_logger.debug("validateKey() finished");
		} catch(ConformanceTestException cte) {
			fail(cte);
		}
    }
	
	//Confirm that the certificate subjectAltName includes FASC-N and that it matches CHUID
	@DisplayName("PKIX.12 test")
    @ParameterizedTest(/*name = "{index} => oid = {0}"*/)
    //@MethodSource("pKIX_x509TestProvider2")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_12(String oid, String requiredOid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		//Check that the oid passed in is not null
		if (oid == null) {
			ConformanceTestException e = new ConformanceTestException("OID is null");
			fail(e);
		}
		
    	if (requiredOid == null || requiredOid.length() == 0) {
    		ConformanceTestException e = new ConformanceTestException("Required OID value passed in is null or empty");
			fail(e);
    	}
    	
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
				
		CardHolderUniqueIdentifier o2 = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		
		if (o2 == null) {
			ConformanceTestException e = new ConformanceTestException("Couldn't read CHUID container from cache");
			fail(e);
		}
		
		byte[] fascn = o2.getfASCN();
		
		if (fascn == null || fascn.length == 0) {
			ConformanceTestException e = new ConformanceTestException("FASC-N in CHUID is null or empty");
			fail(e);
		}

		assertTrue(matchFascn(cert, fascn, requiredOid), "Certificate doesn't contain " + Hex.encodeHexString(fascn));
	}
	
	//Confirm that expiration of certificate is not later than expiration of card
	@DisplayName("PKIX.13 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_13(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;		
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		
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
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);

		PublicKey pubKey = cert.getPublicKey();
		// Only do this if this is an RSA key
		if(pubKey instanceof RSAPublicKey) {
			//confirm that public exponent >= 65537
			BigInteger be = BigInteger.valueOf(65537);
			assertTrue(((RSAPublicKey) (pubKey)).getPublicExponent().compareTo(be) >= 0, "Public exponent is not >= 65537" );
		} 		
    }

	//Confirm digitalSignature and nonRepudiation bits are set
	@DisplayName("PKIX.15 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_DigSigx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_15(String oid, TestReporter reporter) {
		PKIX_Test_4(oid, reporter);
	}

	// Confirm Key Management certificates for elliptic curve keys have keyAgreement bit set
	// If the public key algorithm is RSA, then the keyUsage extension shall only assert the
	// keyEncipherment bit. If the algorithm is Elliptic Curve key, then the keyUsage extension
	// shall only b assert the keyAgreement bit.	@DisplayName("PKIX.16 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_KeyMgmtx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_16(String oid, TestReporter reporter) {
		PKIX_Test_4(oid, reporter);
    }
	
	// Confirm Key Management certificates for elliptic curve keys have keyAgreement bit set
	// If the public key algorithm is RSA, then the keyUsage extension shall only assert the
	// keyEncipherment bit. If the algorithm is Elliptic Curve key, then the keyUsage extension
	// shall only assert the keyAgreement bit.

	@DisplayName("PKIX.17 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_KeyMgmtx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_17(String oid, TestReporter reporter) {
		PKIX_Test_4(oid, reporter);
    }
	
	//Confirm that id- fpki-common-cardAuth 2.16.840.1.101.3.2.1.3.17 OID is asserted in certificate policies
	@DisplayName("PKIX.18 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_18(String oid, String policyOid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;		
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		
		//Get certificate policies extension
		byte[] cpex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_ce_certificatePolicies"));
		
		//Confirm certificate policies extension is present
		assertTrue(cpex != null, "Certificate policies extension is absent");
		
		CertificatePolicies policies = null;
		try {
			policies = CertificatePolicies.getInstance(JcaX509ExtensionUtils.parseExtensionValue(cpex));
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
	
	//Confirm extendedKeyUsage extension is present and is marked critical
	@DisplayName("PKIX.19 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_19(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;		
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		
		//Get eku extension
		byte[] cpex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_ce_extKeyUsage"));
		
		//Confirm eku extension is present
		assertTrue(cpex != null, "EKU extension is absent");
    }

	//Confirm id-PIV-cardAuth is asserted and no other OID is asserted
	@DisplayName("PKIX.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_20(String oid, String parameters, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		Map<String, List<String>> pmap = ParameterUtils.MapFromString(parameters, ",");
		List<String> ekuOids = pmap.get(APDUConstants.containerOidToNameMap.get(oid));
		String ekuOid = ekuOids.get(0);

		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		
		//Get certificate policies extension
		byte[] ekuex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_ce_extKeyUsage"));
		
		//Confirm EKU extension is present
		assertTrue(ekuex != null, "Extended key usage extension is absent");
		
		ExtendedKeyUsage eku = null;
		try {
			eku = ExtendedKeyUsage.getInstance(JcaX509ExtensionUtils.parseExtensionValue(ekuex));
		} catch (IOException e) {
			fail(e);
		}
		
		assertNotNull(eku);
		KeyPurposeId[] kpilist = eku.getUsages();
		assertTrue(kpilist.length == 1, "Extended Key Usage keyPurposeId asserts more than one OID");
    	assertTrue (ekuOid.compareTo(kpilist[0].getId()) == 0, "Certificate does not contain " + ekuOid);
    }

	@DisplayName("PKIX.21 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_CardAuthx509TestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_21(String oid, String ekuOid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);

		//Get certificate policies extension
		byte[] ekuex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_ce_extKeyUsage"));
		
		//Confirm certificate policies extension is present
		assertTrue(ekuex != null, "Certificate policies extension is absent");
		
		ExtendedKeyUsage eku = null;
		try {
			eku = ExtendedKeyUsage.getInstance(JcaX509ExtensionUtils.parseExtensionValue(ekuex));
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

	//An accessMethod containing id-ad-caIssuers is present
	@DisplayName("PKIX.22 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_22(String oid, TestReporter reporter) {
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;

		//Get authorityInformationAccess extension
		byte[] aiaex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));

		if (aiaex != null) {
			AuthorityInformationAccess aia = null;
			try {
				aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(aiaex));
				if (aiaContainsAccessMethod(aia, X509ObjectIdentifiers.crlAccessMethod)) {
					rv = true;
				}
			} catch (Exception e) {
				s_logger.error("AIA decoding failed: " + e.getMessage());
			}
		} else {
			ConformanceTestException e  = new ConformanceTestException("No AIA is present.");
		}
		assertTrue (rv, "An accessMethod containing " +  X509ObjectIdentifiers.crlAccessMethod.toString() + " is not present");
	}

	//Check CRL DP for ".crl"
	@DisplayName("PKIX.24 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_24(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;

		byte[] extVal = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
		if (extVal != null) {
			try {
				CRLDistPoint crldp = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extVal));
				if (crldpEndWithCRL(crldp)) {
					rv = true;
				}
			} catch (Exception e) {
				s_logger.error("CRLDP decoding failed: " + e.getMessage());
			}
		} else {
			s_logger.error("No CRL distribution point present");
		}
		assertTrue(rv, "CRL DP does not end with .crl");
	}

	//The authorityInfoAccess field points to a file that has an extension of ".p7c" containing a
	//certs-only CMS message
	@DisplayName("PKIX.25 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("pKIX_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_25(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
				      
        byte[] extVal = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));
        assertNotNull(extVal);
        
    	try {
			AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extVal));
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
		            		    byte[] dataBuffer = new byte[1024];
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
										
										X509CertificateHolder certificateHolder = certIt.next();
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
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;		
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		
		Calendar cal = Calendar.getInstance();
		Date today = cal.getTime();
		
		assertTrue(cert.getNotAfter().compareTo(today) >= 0, "Signing certificate expired " + cert.getNotAfter());
       
    }
	
	//GeneralName field exists that contain a URI asserting a Card UUID as specified by [RFC4122, Section 3] 
	//that matches the GUID value in the CHUID.
	@DisplayName("PKIX.27 test")
    @ParameterizedTest(/*name = "{index} => oid = {0}"*/)
    //@MethodSource("pKIX_x509TestProvider2")
    //@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_27(String oid, String requiredOid, TestReporter reporter) {
		//Check that the oid passed in is not null
		if (oid == null) {
			ConformanceTestException e = new ConformanceTestException("OID is null");
			fail(e);
		}
		
    	if (requiredOid == null || requiredOid.length() == 0) {
    		ConformanceTestException e = new ConformanceTestException("Required OID value passed in is null or empty");
			fail(e);
    	}
    	
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
				
		CardHolderUniqueIdentifier o2 = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		
		if (o2 == null) {
			ConformanceTestException e = new ConformanceTestException("Couldn't read CHUID container from cache");
			fail(e);
		}
		
		byte[] guid = o2.getgUID();
		
		if (guid == null || guid.length == 0) {
			ConformanceTestException e = new ConformanceTestException("GUID is null or empty");
			fail(e);
		}

		assertTrue(matchUuid(cert, guid), "Certificate doesn't contain " + Hex.encodeHexString(guid));
	}
	
	//No other name forms appear in the subjectAltName extension.
	@DisplayName("PKIX.28 test")
    @ParameterizedTest(/*name = "{index} => oid = {0}"*/)
    //@MethodSource("pKIX_x509TestProvider2")
    //@ArgumentsSource(ParameterizedArgumentsProvider.class)
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void PKIX_Test_28(String oid, TestReporter reporter) {
		//Check that the oid passed in is not null
		if (oid == null) {
			ConformanceTestException e = new ConformanceTestException("OID is null");
			fail(e);
		}
    	
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
				
		CardHolderUniqueIdentifier o2 = (CardHolderUniqueIdentifier) AtomHelper.getDataObject(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
		
		if (o2 == null) {
			ConformanceTestException e = new ConformanceTestException("Couldn't read CHUID container from cache");
			fail(e);
		}
		
		byte[] guid = o2.getgUID();
		
		if (guid == null || guid.length == 0) {
			ConformanceTestException e = new ConformanceTestException("GUID is null or empty");
			fail(e);
		}

		ArrayList<Integer> types = new ArrayList<Integer>(Arrays.asList(0, 6));
		assertTrue(onlyMatchesTypes(cert, types) , "Certificate doesn't contain " + Hex.encodeHexString(guid));
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
				cert = chuid.getChuidSignerCert();
			} else {
				X509CertificateDataObject certObject = (X509CertificateDataObject) obj;
				cert = certObject.getCertificate();
			}
			rv.put(oid, cert);
		}
		return rv;
	}

	//The accessLocation for the id-ad-caIssuers AccessMethod is of type uniformResourceIdentifier.
	@DisplayName("PKIX.29 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_29(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;
		byte[] aiaex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));
		if (aiaex != null) {
			try {
				AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(aiaex));
				if (aiaContainsAccessMethod(aia, X509ObjectIdentifiers.crlAccessMethod)) {
					if (accessMethodContainsURI(aia, X509ObjectIdentifiers.crlAccessMethod)) {
						rv = true;
					}
				}
			} catch (Exception e) {
				s_logger.error("Exception decoding AIA", e.getMessage());
			}
		} else {
			s_logger.error("No AIA is present");
		}
		assertTrue (rv, "The accessLocation for this AccessMethod is not of type uniformResourceIdentifier.");
	}

	//Confirm that the access location for caIssuers is http protocol
	@DisplayName("PKIX.30 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_30(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;

		byte[] aiaex = cert.getExtensionValue(PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess"));

		if (aiaex != null) {
			try {
				AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(JcaX509ExtensionUtils.parseExtensionValue(aiaex));
				if (aiaContainsAccessMethod(aia, X509ObjectIdentifiers.crlAccessMethod)) {
					if (accessMethodContainsURI(aia, X509ObjectIdentifiers.crlAccessMethod)) {
						if (aIAUriContainsHttp(aia, X509ObjectIdentifiers.crlAccessMethod)) {
							rv = true;
						}
					}
				}
			} catch (Exception e) {
				s_logger.error("AIA decoding failed: " + e.getMessage());
			}
		} else {
			s_logger.error("No AIA extension present.");
		}
		assertTrue (rv, "URI for id-ad-caIssuers is not http:");
	}

	//The URI scheme for id-ce-cRLDistributionPoints is "http" (not "https")
	@DisplayName("PKIX.31 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("pKIX_x509TestProvider")
	@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void PKIX_Test_31(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		X509Certificate cert = AtomHelper.getCertificateForContainer(AtomHelper.getDataObject(oid));
		assertNotNull(cert, "Certificate could not be read for " + oid);
		boolean rv = false;

		byte[] extVal = cert.getExtensionValue(Extension.cRLDistributionPoints.getId());
		if (extVal != null) {
			try {
				CRLDistPoint crldp = CRLDistPoint.getInstance(JcaX509ExtensionUtils.parseExtensionValue(extVal));
				if (crldpStartsWithHTTP(crldp)) {
					rv = true;
				}
			} catch (Exception e) {
				s_logger.error("CRLDP decoding failed: " + e.getMessage());
			}
		} else {
			s_logger.error("No CRL distribution point present");
		}
		assertTrue(rv, "URI scheme for id-ce-cRLDistributionPoints is not http:");
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
		
		X509Certificate cert5 = ((CardHolderUniqueIdentifier) o5).getChuidSignerCert();
		assertNotNull(cert5, "Certificate retrived from X509CertificateDataObject object is NULL");
		// TODO: Technically, we should be checking biometric containers for embedded content signer certs
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
		
		String aiaOid = PKIX_X509DataObjectIdentifiers.get("X509_id_pe_authorityInfoAccess");
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
		
		X509Certificate cert5 = ((CardHolderUniqueIdentifier) o5).getChuidSignerCert();
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
		
		X509Certificate cert5 = ((CardHolderUniqueIdentifier) o5).getChuidSignerCert();
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
	
	/**
	 * Attempts to match the UUID in the GeneralNames in the Subject Alternative Name extension in 
	 * a certificate with the specified UUID
	 * @param certificate the certificate to decode
	 * @param identifier the UUID to match
	 * @return true if the certificate's subject alternative name contains the UUID represented by a Type-Id of 6
	 */
    
    private boolean matchUuid(X509Certificate certificate, byte[] identifier) {
		boolean result = false;
		byte[] sanEncoded = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

		if (sanEncoded != null) {
			ASN1Primitive sanBytes;
			try {
				sanBytes = JcaX509ExtensionUtils.parseExtensionValue(sanEncoded);
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
			try {
				GeneralNames sans = GeneralNames.getInstance(sanBytes);
				GeneralName[] sanArray = sans.getNames();
				for (GeneralName gn : sanArray) {
					if (gn.getTagNo() == 6) {
						DERIA5String encodedUuid = DERIA5String.getInstance(gn.getName());
						byte[] urnUuid = encodedUuid.getString().getBytes();
						byte[] uuid = Arrays.copyOfRange(urnUuid, "urn:uuid:".length(), urnUuid.length); 
						s_logger.debug("UUID: {}", new String(uuid));
						
						byte[] test = new String(uuid).getBytes();
						result = Arrays.equals(uuid, test);
					}
				}
			} catch (Exception e) {
				s_logger.error("Exception while matching UUID: ", e.getMessage());
			}
		} else {
			String message = "Subject alternative name extension is null";
			s_logger.error(message);
		}

		return result;
	}
    
	/**
	 * Attempts to match the FASC-N in the GeneralNames in the Subject Alternative Name extension in 
	 * a certificate with the specified FASC-N
	 * @param certificate the certificate to decode
	 * @param identifier the FASC-N to match
	 * @return true if the certificate's subject alternative name contains the piv-id-FASC-N represented by a Type-Id of 0
	 */
    private boolean matchFascn(X509Certificate certificate, byte[] identifier, String requiredOid) {
		boolean result = false;
		byte[] sanEncoded = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

		if (sanEncoded != null) {
			ASN1Primitive sanBytes;
			try {
				sanBytes = JcaX509ExtensionUtils.parseExtensionValue(sanEncoded);
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
			GeneralNames sans = GeneralNames.getInstance(sanBytes);
			GeneralName[] sanArray = sans.getNames();
			try {
				for (GeneralName gn : sanArray) {
					if (gn.getTagNo() == 0) {
						ASN1Sequence seq = ASN1Sequence.getInstance(gn.getName());
						ASN1ObjectIdentifier oID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
						if (oID.toString().equals(requiredOid)) {
							ASN1TaggedObject onValue = ASN1TaggedObject.getInstance(seq.getObjectAt(1)); 
							byte[] encodedFascn = ASN1OctetString.getInstance(onValue.getObject()).getOctets();
							if (encodedFascn != null &&  (Arrays.equals(encodedFascn, identifier))) {
								result = Arrays.equals(encodedFascn, identifier);
								s_logger.debug("FASCN: {}", Hex.encodeHexString(encodedFascn));
							}
						} else {
							s_logger.error("Found superfluous OID: ", oID.toString());
						}
					}
				}
			} catch (Exception e) {
				s_logger.error("Exception while matching FASC-N: ", e.getMessage());
			}
		} else {
			String message = "Subject alternative name extension is null";
			s_logger.error(message);
		}

		return result;
	}
    
    /**
     * Determines whether the subject alternative name extension contains no GeneralNames
     * besides the types specified in a given list
     * @param certificate to be parsed
     * @param allowedTypeIds list of allowable type IDs
     * @return true if no other IDs in the allowed list are present
     */
    
    private boolean onlyMatchesTypes(X509Certificate certificate, ArrayList<Integer> allowedTypeIds) {
		boolean result = false;
		byte[] sanEncoded = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

		if (sanEncoded != null) {
			ASN1Primitive sanBytes;
			try {
				sanBytes = JcaX509ExtensionUtils.parseExtensionValue(sanEncoded);
			} catch (IOException e) {
				e.printStackTrace();
				return false;
			}
			GeneralNames sans = GeneralNames.getInstance(sanBytes);
			GeneralName[] sanArray = sans.getNames();
			try {
				for (GeneralName gn : sanArray) {
					if (!allowedTypeIds.contains(gn.getTagNo())) {
						s_logger.error("Found invalid Type-Id {}", gn.getTagNo());
						return false;
					}
				}
			} catch (Exception e) {
				s_logger.error("Exception while matching FASC-N: ", e.getMessage());
				return false;
			}
		} else {
			String message = "Subject alternative name extension is null";
			s_logger.error(message);
			return false;
		}
		return true;
	}    
}
