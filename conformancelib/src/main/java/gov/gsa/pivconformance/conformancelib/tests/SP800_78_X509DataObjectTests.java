package gov.gsa.pivconformance.conformancelib.tests;

import java.security.AlgorithmParameters;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.stream.Stream;

import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.ValidatorHelper;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
//import org.bouncycastle.asn1.x9.ECNamedCurveTable;
//import org.bouncycastle.asn1.x9.X9ECParameters;
//import org.bouncycastle.jce.interfaces.ECPublicKey;
//import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;

import static org.junit.jupiter.api.Assertions.*;

public class SP800_78_X509DataObjectTests {
	
	static Logger s_logger = LoggerFactory.getLogger(SP800_78_X509DataObjectTests.class);

	/*
X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7,
X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7,
X509_CERTIFICATE_FOR_DIGITAL_CERTIFICATE_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7|1.2.840.10045.2.1+1.3.132.0.34,
X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7|1.2.840.10045.2.1+1.3.132.0.34

Gets converted to:

Map<String, List<String, String>>
add("X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID", new List<String>("1.2.840.113549.1.1.1+NULL","1.2.840.10045.2.1+1.2.840.10045.3.1.7");


	 * TODO: Evaluate this atom for suitability as a 78-3 table. Table 3-1
	 * establishes specific requirements for cryptographic algorithms and key sizes
	 * for each key type. In addition to the key sizes, keys must be generated using
	 * secure parameters. Rivest, Shamir, Adleman (RSA) keys must be generated using
	 * a public exponent of 65 537. Elliptic curve keys must correspond to one of
	 * the following recommended curves from [FIPS186]: + Curve P-256; or + Curve
	 * P-384. To promote interoperability, this specification further limits PIV
	 * Authentication and Card Authentication elliptic curve keys to a single curve
	 * (P-256).2 PIV cryptographic keys for digital signatures and key management
	 * may use P-256 or P-384, based on application requirements. There is no phase
	 * out date specified for either curve. If the PIV Card Application supports the
	 * virtual contact interface [SP800-73] and the digital signature key, the key
	 * management key, or any of the retired key management keys are elliptic curve
	 * keys corresponding to Curve P-384, then the PIV Secure Messaging key shall
	 * use P-384, otherwise it may use P-256 or P-384.
	 *  
	 *           Table 3-1. Algorithm and Key Size Requirements for PIV Key Types
	 * -----------------------------------+-----------------------------------------------
	 * PIV Key Type                       | Algorithms and Key Sizes PIV
	 * -----------------------------------+-----------------------------------------------
	 * PIV Authentication key             | RSA (2048 bits)
	 *                                    | ECDSA (Curve P-256)
	 * -----------------------------------+-----------------------------------------------
	 * Asymmetric Card Authentication key | RSA (2048 bits)
	 *                                    | ECDSA (Curve P-256)
	 * -----------------------------------+-----------------------------------------------
	 * Symmetric Card Authentication key  | 3TDEA3 AES-128, AES-192, or AES-256
	 * -----------------------------------+-----------------------------------------------
	 * Digital signature key              | RSA (2048 bits) 
	 *                                    | ECDSA (Curve P-256 or P-384)
	 * -----------------------------------+-----------------------------------------------
	 * Key Management Key                 | RSA key transport (2048 bits); 
	 *                                    | ECDH (Curve P-256 or P-384)
	 * -----------------------------------+-----------------------------------------------
	 * PIV Secure Messaging key           | ECDH (Curve P-256 or P-384)
	 * -----------------------------------+-----------------------------------------------
	 * 
	 */
	// The key size and types used are in accordance with Table 3-1 of SP80078.
	// Expect to see paramsString contain an containerOid:keyAlgorithmOid
    @DisplayName("SP800-78.1 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_78_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_78_Test_1(String oid, TestReporter reporter) {
    	
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = AtomHelper.getCertificateForContainer(o);
		if(cert == null) {
			Exception e = new Exception("getCertificate returned a null");
			fail(e);
		}
		
		PublicKey pk = cert.getPublicKey();
		if(pk == null) {
			Exception e = new Exception("getPublicKey returned a null");
			fail(e);
		}
		
		String certAlgorithm = pk.getAlgorithm();
		if(certAlgorithm == null) {
			Exception e = new Exception("getAlgorithm returned a null");
			fail(e);
		}
		
		int keylen = 0;	
		if (certAlgorithm.compareTo("RSA") == 0) {
			RSAPublicKey rsaPk = (RSAPublicKey) pk;
			keylen = rsaPk.getModulus().bitLength();
			assertTrue((keylen == 2048 || keylen == 3072), keylen + " is an invalid key length");
		} else if (certAlgorithm.compareTo("EC") == 0) {
			java.security.interfaces.ECPublicKey ec = (java.security.interfaces.ECPublicKey) pk;
			keylen = ec.getParams().getCurve().getField().getFieldSize();
			assertTrue((keylen == 256 || keylen == 384), keylen + " is an invalid key length");
		}
		
		String curveFromCert = "";
		int modulus = 0;
		if(certAlgorithm.compareTo("RSA") == 0) {
			
			RSAPublicKey pk1 = (RSAPublicKey) pk;
			modulus = pk1.getModulus().bitLength();
			
		} else if(certAlgorithm.compareTo("EC") == 0) {
			
			ECPublicKey pk1 = (ECPublicKey) pk;
	        ECParameterSpec ecParameterSpec = pk1.getParams();
	      
	        for (Enumeration<?> names = ECNamedCurveTable.getNames(); names.hasMoreElements(); ) {
	        	
		        String name = (String)names.nextElement();
		        s_logger.debug("name = {}, spec = {}", name, ecParameterSpec.toString());
		        
		        if (ecParameterSpec.toString().matches(String.format("^.*%s.*$", name))) {
		        	curveFromCert = name;
		        	break;
		        }
	        }
		}
		
		String supportedCurve1 = "prime256v1";
		String supportedCurve2 = "prime384v1";	
		
		if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID) == 0) {
			
			if(certAlgorithm.compareTo("RSA") == 0) {
				//check key size
				assertTrue(modulus == 2048);
			}
			else if(certAlgorithm.compareTo("EC") == 0) {					      
			    //Confirm that the curve in the cert is prime256v1
			    assertTrue(supportedCurve1.compareTo(curveFromCert) == 0);
			}
			else {
				assertTrue(false);
			}
			
		} else if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID) == 0) {
			
			if(certAlgorithm.compareTo("RSA") == 0) {
				//check key size
				assertTrue(modulus == 2048);
			}
			else if(certAlgorithm.compareTo("EC") == 0) {

			    //Confirm that the curve in the cert is prime256v1 or prime384v1
				assertTrue(supportedCurve1.compareTo(curveFromCert) == 0 || supportedCurve2.compareTo(curveFromCert) == 0);
			}
			else {
				assertTrue(false);
			}
		} else if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID) == 0) {
			
			if(certAlgorithm.compareTo("RSA") == 0) {
				//check key size
				assertTrue(modulus == 2048);
			}
			else if(certAlgorithm.compareTo("EC") == 0) {
			    //Confirm that the curve in the cert is prime256v1 or prime384v1
				assertTrue(supportedCurve1.compareTo(curveFromCert) == 0 || supportedCurve2.compareTo(curveFromCert) == 0);
			}
			else {
				assertTrue(false);
			}
			
		} else if(oid.compareTo(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID) == 0) {
		
			if(certAlgorithm.compareTo("RSA") == 0) {
				//check key size
				assertTrue(modulus == 2048);
			}
			else if(certAlgorithm.compareTo("EC") == 0) {
			    //Confirm that the curve in the cert is prime256v1 or prime384v1
				assertTrue(supportedCurve1.compareTo(curveFromCert) == 0);
			}
			else {
				assertTrue(false);
			}
		}
		else {
			// Let's for now assume this is a content signing cert. 
			// TODO: Make special block to handle content signing cert and SMCS (CVC)
		}
    }

    //Table 3-2 ECDSA Ensure that ECDSA key is curve P-256 or P-384
    // TODO: Refactor using Algorithm class
	//Curve P-256: ansip256r1 1.2.840.10045.3.1.7
	//ansip256r1 ::= { iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3) prime(1) 7 }
	//Curve P-384: ansip384r1 1.3.132.0.34
	//ansip384r1 ::= { iso(1) identified-organization(3) certicom(132) curve(0) 34 }
    @DisplayName("SP800-78.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_78_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_78_Test_2(String oid, TestReporter reporter) {
		fail("sp800_78_Test_2 not implemented");
    }
    
    /*
     * The signatureAlgorithm value is in accordance with Table 3-3 of SP80078.
     * If the algorithm value is id-RSASSA-PSS, verify that the signature->parameters
     * field is populated with SHA-256 (OID = 2.16.840.1.101.3.4.2.1). For the other
     * RSA algorithms, the parameters field is populated with NULL. For ECDSA, the
     * parameters field is absent. This atom might be weirdly abstracted but should
     * work for all certificate containers
     */
    @DisplayName("SP800-78.3 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_78_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_78_Test_3(String oid, TestReporter reporter) {
    	PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = AtomHelper.getCertificateForContainer(o);
		if(cert == null) {
			Exception e = new Exception("getCertificate returned a null");
			fail(e);
		}

		String sha256Oid = "2.16.840.1.101.3.4.2.1";
		String sha256WithRSAEncryption = "1.2.840.113549.1.1.11";
		String rSASSA_PSS =  "1.2.840.113549.1.1.10";
		String ecdsaWithSHA256 = "1.2.840.10045.4.3.2";
		String ecdsaWithSHA384 = "1.2.840.10045.4.3.3";

		try {
			String signatureAlgOID = cert.getSigAlgOID();
			String name = cert.getSigAlgName();
			if (signatureAlgOID.compareTo(sha256WithRSAEncryption) == 0) {
				byte[] params = cert.getSigAlgParams();
				if (params != null) {
					// RFC 4055: All implementations MUST accept both NULL and absent parameters as
					// legal and equivalent encodings. Certs generated by BC end encode a NULL
					// element which we manually decode and ignore if the bytes are { 5, 0 }
					String errMsg = "Parameter must NOT be supplied for " + name + ".  Value of params " + Hex.encodeHexString(params);
					assertTrue ((params[0] != 5 || params[1] != 0), errMsg);
				} else {
					s_logger.debug("Setting BC cert's params to null");
					params = null;
				}
				assertTrue(params == null, "No such algorithm or parameters not available for (" + cert.getSigAlgName());
			} else if (signatureAlgOID.compareTo(rSASSA_PSS) == 0) {
				byte[] params = cert.getSigAlgParams();
				assertNotNull(params, "Parameters are not specified");
				AlgorithmParameters aps = AlgorithmParameters.getInstance(cert.getSigAlgName());
				assertNotNull(aps, "Algorithm parameters is null");
				aps.init(params);
				PSSParameterSpec pssps = aps.getParameterSpec(PSSParameterSpec.class);
				assertNotNull(pssps, "Parameter spec is null");
				String digestAlg = pssps.getDigestAlgorithm();
				assertTrue(digestAlg.toLowerCase().toLowerCase().replaceAll("-", "").equals("sha256"));
			} else if (signatureAlgOID.compareTo(ecdsaWithSHA256) == 0) {
				byte[] params = cert.getSigAlgParams();
				if (params != null)
					s_logger.error("Parameter must NOT be supplied for " + signatureAlgOID + ".  Value of params " + Hex.encodeHexString(params));
				assertTrue(params == null, "Non-conformant signature algorithm OID");
			} else if (signatureAlgOID.compareTo(ecdsaWithSHA384) == 0) {
				byte[] params = cert.getSigAlgParams();
				if (params != null)
					s_logger.error("Parameter must NOT be supplied for " + signatureAlgOID + ".  Value of params " + Hex.encodeHexString(params));
				assertTrue(params == null, "Non-conformant signature algorithm OID");
			} else {
				assertTrue(false, "Signature algorithm (" + signatureAlgOID + ") is not an allowable algorithm");
			}
		} catch (Exception e) {
			String msg = e.getMessage();
			s_logger.error(msg);
			fail(msg);
		}
	}

	// methods below are no longer used in conformance test tool and are only retained because they are sometimes useful for
	// testing the atoms themselves
	@SuppressWarnings("unused")
    private static Stream<Arguments> sp800_78_x509TestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
