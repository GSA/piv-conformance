package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObject;

public class SP800_78_X509DataObjectTests {
	/*
X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7,
X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7,
X509_CERTIFICATE_FOR_DIGITAL_CERTIFICATE_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7|1.2.840.10045.2.1+1.3.132.0.34,
X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7|1.2.840.10045.2.1+1.3.132.0.34

Gets converted to:

Map<String, List<String, String>>
add("X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID", new List<String>("1.2.840.113549.1.1.1+NULL","1.2.840.10045.2.1+1.2.840.10045.3.1.7");


	

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
		int modulus = 0;
		if(pubKey instanceof RSAPublicKey) {
			
			RSAPublicKey pk = (RSAPublicKey) pubKey;
			modulus = pk.getModulus().bitLength();
		}else if(pubKey instanceof ECPublicKey) {
			
			ECPublicKey pk = (ECPublicKey) pubKey;
	        ECParameterSpec ecParameterSpec = pk.getParameters();
	        
	        
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
		}
		
		
		String supportedCurve1 = "prime256v1";
		String supportedCurve2 = "secp384r1";

		
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
		
    }
    
    //Table 3-2 ECDSA Ensure that ECDSA key is curve P-256 or P-384
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
	        ECParameterSpec ecParameterSpec = pk.getParameters();
	        
	        
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
			//byte [] xNULL = {0x05, 0x00};
			// java is returning null for RSA params
			///assertTrue(Arrays.equals(params, xNULL), "No such algorithm or parameters not available for (" + cert.getSigAlgName());
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
