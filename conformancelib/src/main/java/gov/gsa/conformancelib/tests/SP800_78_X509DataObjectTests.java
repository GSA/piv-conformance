package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

<<<<<<< HEAD
=======
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
>>>>>>> origin/database-work
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;

<<<<<<< HEAD
=======
import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.ParameterUtils;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
>>>>>>> origin/database-work
import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
<<<<<<< HEAD
=======
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
>>>>>>> origin/database-work
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;

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
    //@MethodSource("sp800_78_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_78_Test_1(String oid, String paramsString, TestReporter reporter) {
    	
		PIVDataObject o = AtomHelper.getDataObject(oid);		
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		Map<String,List<String>> mp = ParameterUtils.MapFromString(paramsString);
		
		// Process the map if non-empty.  If the map is empty, an exception will
		// have already been thrown and caught by MapFromString(), so we can safely
		// drop through.
		
		if (!mp.isEmpty()) {
			// Look for the matching certificate (by container OID) in the list
			
			Iterator<String> it = mp.keySet().iterator();
			boolean allowable = false;
			
			while (it.hasNext()) {
				String containerKey = it.next(); // will be an oid for a certificate container
				if (containerKey.compareTo(oid) == 0) { // matches this certificate container we're inspecting
					//AlgorithmIdentifier ai = new DefaultAlgorithmIdentifierFinder().find(( cert.getPublicKey().getAlgorithm() );

					PublicKey pubKey = cert.getPublicKey();
					String certAlgorithmOid = pubKey.getAlgorithm();
					List<String> allowedOids = mp.get(containerKey); // sub-parameters
					allowable = (allowedOids.contains(certAlgorithmOid));
				}
			}
			assertTrue(allowable);
		}
    }
    
    //Table 3-2 ECDSA Ensure that ECDSA key is curve P-256 or P-384
    @DisplayName("SP800-78.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_78_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_78_Test_2(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);
		
		String supportedCurve = "prime256v1";
		
		PublicKey pubKey = cert.getPublicKey();

		if(pubKey instanceof ECPublicKey) {
		
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
    //@MethodSource("sp800_78_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_78_Test_3(String oid, String paramsString, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);
<<<<<<< HEAD
                
        List<String> algList = new ArrayList<String>();
        
        algList.add("1.2.840.113549.1.1.5");
        algList.add("1.2.840.113549.1.1.10");
        algList.add("1.2.840.113549.1.1.11");
        algList.add("1.2.840.10045.4.3.2");
        algList.add("1.2.840.10045.4.3.3");
        
        X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);        
        
        String sigAlgFromCert = cert.getSigAlgOID();
        
        assertTrue(algList.contains(sigAlgFromCert));
    }    	
    
	// methods below are no longer used in conformance test tool and are only retained because they are sometimes useful for
	// testing the atoms themselves
	@SuppressWarnings("unused")
=======
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		Map<String,List<String>> mp = ParameterUtils.MapFromString(paramsString);

		// Process the map if non-empty. If the map is empty, an exception will
		// have already been thrown and caught by MapFromString(), so we can safely
		// drop through.

		if (!mp.isEmpty()) {
			String sigAlgOid = cert.getSigAlgOID();

			boolean found = mp.containsKey(sigAlgOid);
			assertTrue(found == true, "Signature algorithm (" + sigAlgOid + ") is not an allowable algorithm");
			List<String> databaseSigAlgParams = mp.get(sigAlgOid);
			try {
				AlgorithmParameters ap = AlgorithmParameters.getInstance(cert.getSigAlgName());
				// RSA-PSS or ECDSA in this block at least for FIPS 201-2
				if (!databaseSigAlgParams.isEmpty()) { // RSASSA-PSS
					assertTrue(databaseSigAlgParams.contains(sigAlgOid), "Non-conformant signature algorithm OID");
				} else {
					assertTrue(databaseSigAlgParams.contains(""), "Non-conformant signature algorithm OID");
				}
			} catch (NoSuchAlgorithmException e) {
				// Certs with legit RSA with SHA256 will end up here, so as
				// long as the specified parameter is "null" it's a pass.
				assertTrue(databaseSigAlgParams == null, "No such algorithm or parameters not available for (" + cert.getSigAlgName());
			}
		}
	}

>>>>>>> origin/database-work
    private static Stream<Arguments> sp800_78_x509TestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
