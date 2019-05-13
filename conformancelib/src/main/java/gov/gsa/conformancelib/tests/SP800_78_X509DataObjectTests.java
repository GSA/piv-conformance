package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Stream;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
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
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.ParameterUtils;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;

public class SP800_78_X509DataObjectTests {
	
	// The key sizes used are in accordance with Table 3-1 of SP80078.
	// Expect to see paramsString contain an algorithm:parameter
    @DisplayName("SP800-78.1 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_78_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_78_Test_1(String oid, String paramsString, TestReporter reporter) {
    	
		PIVDataObject o = AtomHelper.getDataObject(oid);		
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		Map<String, String> mp = ParameterUtils.MapFromString(paramsString);
		int keyRef = APDUConstants.oidToContainerIdMap.get(oid);
		
		// Process the map if non-empty.  If the map is empty, an exception will
		// have already been thrown and caught by MapFromString(), so we can safely
		// drop through.
		
		if (!mp.isEmpty()) {

			// Depending on the cert type, only mp->key and optional mp->value are allowed

			switch(keyRef) {
			
			case APDUConstants.PIV_AUTHENTICATION_KEY_ID:
			case APDUConstants.CARD_AUTHENTICATION_KEY_ID:
			case APDUConstants.DIGITAL_SIGNATURE_KEY_ID:			
					PublicKey pubKey = cert.getPublicKey();
					String algorithmOid = pubKey.getAlgorithm();
					String algorithmName = cert.getSigAlgName();
					int actualKeyLength, claimedKeyLength = 0;
					
					if(pubKey instanceof RSAPublicKey) {				
						RSAPublicKey pk = (RSAPublicKey) pubKey;
						claimedKeyLength = (algorithmName.indexOf("2048") >= 0) ? 2048 : (algorithmName.indexOf("3072") >= 0) ? 3072 : -1;
						actualKeyLength = pk.getModulus().bitLength();
						
						assertTrue(mp.containsValue(actualKeyLength), 
								"Key length of " + actualKeyLength + " for RSA doesn't comply with Table 3-1 SP 800-73-4");
						assertTrue(mp.containsKey(algorithmOid), 
								"Key algorithm for OID " + algorithmOid + " doesn't comply with Table 3-1 SP 800-73-4");
						assertTrue(actualKeyLength == claimedKeyLength, 
								"Actual key length (" + actualKeyLength + ") doesn't match algorithm (" + algorithmName + ")");
						
					} else if (pubKey instanceof ECPublicKey) {
						ECDSAPublicKey pk = (ECDSAPublicKey) pubKey;	    
					    claimedKeyLength = (cert.getSigAlgName().indexOf("256") >= 0) ? 256 : (cert.getSigAlgName().indexOf("384") >= 0) ? 384 : -1;
						actualKeyLength = Integer.parseInt(pk.getPrimeModulusP().toString());
						assertTrue(mp.containsValue(actualKeyLength), 
								"Key length of " + actualKeyLength + " for ECDSA doesn't comply with Table 3-1 SP 800-73-4");
						assertTrue(mp.containsKey(algorithmOid), 
								"Key algorithm for OID " + algorithmOid + " doesn't comply with Table 3-1 SP 800-73-4");
						assertTrue(actualKeyLength == claimedKeyLength, 
								"Actual key length (" + actualKeyLength + ") doesn't match algorithm (" + algorithmName + ")");
					}
					break;
				default:
					break;
			}
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
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		Map<String, String> mp = ParameterUtils.MapFromString(paramsString);
		int keyRef = APDUConstants.oidToContainerIdMap.get(oid);

		// Process the map if non-empty. If the map is empty, an exception will
		// have already been thrown and caught by MapFromString(), so we can safely
		// drop through.

		if (!mp.isEmpty()) {
			String sigAlgOid = cert.getSigAlgOID();

			boolean found = mp.containsKey(sigAlgOid);
			assertTrue(found == true, "Signature algorithm (" + sigAlgOid + ") is not an allowable algorithm");
			String databaseSigAlgParam = mp.get(sigAlgOid);
			try {
				AlgorithmParameters ap = AlgorithmParameters.getInstance(cert.getSigAlgName());
				// RSA-PSS or ECDSA in this block
				if (databaseSigAlgParam.length() > 0) { // RSASSA-PSS
					assertTrue(databaseSigAlgParam.compareTo(sigAlgOid) == 0, "Non-conformant signature algorithm OID");
				} else {
					assertTrue(databaseSigAlgParam.compareTo("") == 0, "Non-conformant signature algorithm OID");
				}
			} catch (NoSuchAlgorithmException e) {
				// Certs with legit RSA with SHA256 will end up here, so as
				// long as the specified parameter is "null" it's a pass.
				assertTrue(databaseSigAlgParam == null, "No such algorithm or parameters not available for (" + cert.getSigAlgName());
			}
		}
	}

    private static Stream<Arguments> sp800_78_x509TestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
