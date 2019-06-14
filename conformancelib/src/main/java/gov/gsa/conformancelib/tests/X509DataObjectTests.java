package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;

import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class X509DataObjectTests {
	
	//Container blob is no larger than 1905 bytes
    @DisplayName("SP800-73-4.18 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_18(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
       
        
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		assertTrue(bertlv.length <= 1905);
        
    }
    
    
	//Tags 0x70 and 0x71 are present in that order
    @DisplayName("SP800-73-4.19 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_19(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = ((X509CertificateDataObject) o).getTagList();
		
		BerTag berCertTag = new BerTag(TagConstants.CERTIFICATE_TAG);
		BerTag berCertInfoTag = new BerTag(TagConstants.CERTINFO_TAG);
		
		assertTrue(tagList.contains(berCertTag));
		assertTrue(tagList.contains(berCertInfoTag));
		
		int tagIndex = tagList.indexOf(berCertTag);
		
		assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.CERTIFICATE_TAG));
		assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.CERTINFO_TAG));
        
        
    }
    
	//Tag 0x72 is optionally present and follows tags from 73-4.19
    @DisplayName("SP800-73-4.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_20(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = ((X509CertificateDataObject) o).getTagList();
		
		BerTag berCertTag = new BerTag(TagConstants.CERTIFICATE_TAG);
		BerTag berMSCUIDTag = new BerTag(TagConstants.MSCUID_TAG);
		
		if(tagList.contains(berMSCUIDTag)) {
			
			int tagIndex = tagList.indexOf(berCertTag);
			
			assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.CERTIFICATE_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.CERTINFO_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+2).bytes,TagConstants.MSCUID_TAG));
		}		       
        
    }
    
	//Tag 0xFE is present and follows tags from 73-4.19, 73-4.20
    @DisplayName("SP800-73-4.21 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_21(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = ((X509CertificateDataObject) o).getTagList();
		
		BerTag berCertTag = new BerTag(TagConstants.CERTIFICATE_TAG);
		BerTag berMSCUIDTag = new BerTag(TagConstants.MSCUID_TAG);
		BerTag berEDCTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		assertTrue(tagList.contains(berEDCTag));

		int tagIndex = tagList.indexOf(berCertTag);
		
		if(tagList.contains(berMSCUIDTag)) {
					
			assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.CERTIFICATE_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.CERTINFO_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+2).bytes,TagConstants.MSCUID_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+3).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
			
		}else {
			
			assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.CERTIFICATE_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.CERTINFO_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+2).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
		}
        
    }
    
	//No tags other than (0x70, 0x71, 0x72, 0xFE) are present
    @DisplayName("SP800-73-4.22 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_22(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = ((X509CertificateDataObject) o).getTagList();
		
		List<byte[]> allx509Tags = TagConstants.Allx509Tags();
		for(BerTag tag : tagList) {

			//Check that the tag is present in the all CCC tags list
			boolean present = false;
			for (int i = 0; i < allx509Tags.size(); i++) {
				
				if(Arrays.equals(allx509Tags.get(i), tag.bytes)) {
					present = true;
					break;
				}
			}
			assertTrue(present);
		}
    }

    
	//Confirm that tag 0xFE has length of 0
    @DisplayName("SP800-73-4.23 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_23(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = o.getTagList();
		
		BerTag berEDCTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		assertTrue(tagList.contains(berEDCTag));

		boolean ecHasData =  o.getErrorDetectionCodeHasData();
		
		assertTrue(ecHasData == false);
    }
    
    private static Stream<Arguments> sp800_73_4_x509TestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
