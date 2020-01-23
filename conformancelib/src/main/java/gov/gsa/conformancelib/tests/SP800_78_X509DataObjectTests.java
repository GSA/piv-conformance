package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
//import org.bouncycastle.asn1.x9.ECNamedCurveTable;
//import org.bouncycastle.asn1.x9.X9ECParameters;
//import org.bouncycastle.jce.interfaces.ECPublicKey;
//import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObject;

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
    @MethodSource("sp800_78_x509TestProvider")
    //@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_78_Test_1(String oid, TestReporter reporter) {
    	
		PIVDataObject o = AtomHelper.getDataObject(oid);
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
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
	        ECParameterSpec ecParameterSpec = (ECParameterSpec) pk1.getParams();
	      
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
    @DisplayName("SP800-78.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_78_x509TestProvider")
    //@ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_78_Test_2(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);		
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		
		if(cert == null) {
			Exception e = new Exception("getCertificate returned a null");
			fail(e);
		}
		
		String signatureAlgOID = cert.getSigAlgOID();
		PublicKey pubKey = cert.getPublicKey();
		if(pubKey == null) {
			Exception e = new Exception("getPublicKey returned a null");
			fail(e);
		}
		String certAlgorithm = pubKey.getAlgorithm();

		if(certAlgorithm == null) {
			Exception e = new Exception("getAlgorithm returned a null");
			fail(e);
		}
		
		String curveFromCert = "";
		if(pubKey instanceof ECPublicKey) {
			
			ECPublicKey pk = (ECPublicKey) pubKey;
	        ECParameterSpec ecParameterSpec = pk.getParams();
	        
	        
	        for (Enumeration<?> names = ECNamedCurveTable.getNames(); names.hasMoreElements();) {
	        	
		        String name = (String)names.nextElement();
	
		        X9ECParameters params = ECNamedCurveTable.getByName(name);
	
//		        if (params.getN().equals(ecParameterSpec.getN())
//		            && params.getH().equals(ecParameterSpec.getH())
//		            && params.getCurve().equals(ecParameterSpec.getCurve())
//		            && params.getG().equals(ecParameterSpec.getG())){
//		        	curveFromCert = name;
//		        }
	        }
		}
		
		
		String prime256v1 = "prime256v1";
		String secp384r1 = "secp384r1";
		

		String sha256WithRSAEncryption = "1.2.840.113549.1.1.11";
		String rSASSA_PSS =  "1.2.840.113549.1.1.10";
		String ecdsaWithSHA256 = "1.2.840.10045.4.3.2";
		String ecdsaWithSHA384 = "1.2.840.10045.4.3.3";

		
		if(certAlgorithm.compareTo("RSA") == 0) {
			//check signature algorithm
			assertTrue(signatureAlgOID.compareTo(sha256WithRSAEncryption) == 0 || signatureAlgOID.compareTo(rSASSA_PSS) == 0);
		}
		else if(certAlgorithm.compareTo("EC") == 0) {

			if(curveFromCert.compareTo(prime256v1) == 0) {
				//check signature algorithm
				assertTrue(signatureAlgOID.compareTo(ecdsaWithSHA256) == 0);
			} else if(curveFromCert.compareTo(secp384r1) == 0) {

				//check signature algorithm
				assertTrue(signatureAlgOID.compareTo(ecdsaWithSHA384) == 0);
			} else {
				assertTrue(false);
			}
			
		}
		else {
			assertTrue(false);
		}
    }
    
    /*
     * If the algorithm value is id-RSASSA-PSS, verify that the signature->parameters 
     * field is populated with SHA-256 (OID = 2.16.840.1.101.3.4.2.1). For the other RSA
     * algorithms, the parameters field is populated with NULL (:NULL). 
     * 
     * For ECDSA, the parameters field is absent (:).  
     * 
     * This atom might be weirdly abstracted but should work for all
     * certificate containers
     */
    // TODO: Refactor using Algorithm class
    @DisplayName("SP800-78.3 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_78_x509TestProvider")
    //@ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_78_Test_3(String oid, TestReporter reporter) {

    	PIVDataObject o = AtomHelper.getDataObject(oid);		
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		if(cert == null) {
			Exception e = new Exception("getCertificate returned a null");
			fail(e);
		}
		String signatureAlgOID = cert.getSigAlgOID();

		String sha256Oid = "2.16.840.1.101.3.4.2.1";
		String sha256WithRSAEncryption = "1.2.840.113549.1.1.11";
		String rSASSA_PSS =  "1.2.840.113549.1.1.10";
		String ecdsaWithSHA256 = "1.2.840.10045.4.3.2";
		String ecdsaWithSHA384 = "1.2.840.10045.4.3.3";
		
		List<String> databaseSigAlgParams = new ArrayList<String>();
		if(signatureAlgOID.compareTo(sha256WithRSAEncryption) == 0) {
			byte[] params = cert.getSigAlgParams(); 
			assertTrue(params == null, "No such algorithm or parameters not available for (" + cert.getSigAlgName());			
		} else if(signatureAlgOID.compareTo(rSASSA_PSS) == 0) {
			databaseSigAlgParams.add(sha256Oid);	
		} else if(signatureAlgOID.compareTo(ecdsaWithSHA256) == 0) {
			byte[] params = cert.getSigAlgParams(); 
			byte [] sha256Encoding = {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};	
			assertTrue(Arrays.equals(params, sha256Encoding), "Non-conformant signature algorithm OID");
		} else if(signatureAlgOID.compareTo(ecdsaWithSHA384) == 0) {
			byte[] params = cert.getSigAlgParams(); 
			assertTrue(params == null, "Non-conformant signature algorithm OID");
		} else {
			assertTrue(false, "Signature algorithm (" + signatureAlgOID + ") is not an allowable algorithm");
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
