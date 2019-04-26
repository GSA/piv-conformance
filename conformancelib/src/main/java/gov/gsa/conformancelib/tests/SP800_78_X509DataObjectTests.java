package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.stream.Stream;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.PublicKey;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;

public class SP800_78_X509DataObjectTests {
	
	//Table 3-2 RSA Ensure that RSA key has 2048- or 3072-bit modulus
    @DisplayName("SP800-78.1 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_78_x509TestProvider")
    void sp800_78_Test_1(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
		X509Certificate cert = ((X509CertificateDataObject) o).getCertificate();
		assertNotNull(cert);
				
		PublicKey pubKey = cert.getPublicKey();
		
		if(pubKey instanceof RSAPublicKey) {
			RSAPublicKey pk = (RSAPublicKey) pubKey;
			int bl = pk.getModulus().bitLength();
			assertTrue(bl == 2048 || bl == 3072);
		} 
    }
    
    //Table 3-2 ECDSA Ensure that ECDSA key is curve P-256 or P-384
    @DisplayName("SP800-78.2 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_78_x509TestProvider")
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
    
	//Table 3-3 Ensure that signature algorithm is one of 1.2.840.113549.1.1.5, 1.2.840.113549.1.1.11, 1.2.840.113549.1.1.10, 1.2.840.10045.4.3.2, 1.2.840.10045.4.3.3
    @DisplayName("SP800-78.3 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @MethodSource("sp800_78_x509TestProvider")
    void sp800_78_Test_3(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
                
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
    
    private static Stream<Arguments> sp800_78_x509TestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
