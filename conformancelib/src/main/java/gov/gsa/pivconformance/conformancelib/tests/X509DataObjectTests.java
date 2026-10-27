package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.configuration.ResultReference;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.cardlib.tlv.BerTag;
import gov.gsa.pivconformance.cardlib.tlv.TagConstants;

public class X509DataObjectTests {
    private static final Logger s_logger = LoggerFactory.getLogger(X509DataObjectTests.class);
	
	//Cert container value lengths comply with Table 10, 15, 16, 17, 20-39, 42 of SP 800-73-4
    @DisplayName("SP800-73-4.18 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_18(String oid, TestReporter reporter) {
    	assertTrue(false);  // Abbreviated to make sure we don't fire this - remove entire atom if we don't
    }
    
	//Tags 0x70 and 0x71 are present in that order
    @DisplayName("SP800-73-4.19 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_19(String oid, TestReporter reporter) {
		// if the object is not mandatory and is not present, the test is done
		if(AtomHelper.isOptionalAndAbsent(oid)) {
			s_logger.info("Optional container {} is absent from the card.", oid);
			return;
		} else {
			s_logger.info("Optional container {} is present on the card. Proceeding with test.", oid);
		}		
		PIVDataObject o = AtomHelper.getDataObject(oid);
          
		List<BerTag> tagList = o.getTagList();
		
		BerTag berCertTag = new BerTag(TagConstants.CERTIFICATE_TAG);
		BerTag berCertInfoTag = new BerTag(TagConstants.CERTINFO_TAG);
		
		assertTrue(tagList.contains(berCertTag), "Certificate container: tag 70 is required");
		assertTrue(tagList.contains(berCertInfoTag), "Certificate container: tag 71 is required");
		
		int tagIndex = tagList.indexOf(berCertTag);
		
		assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.CERTIFICATE_TAG));
		assertTrue(tagIndex + 1 < tagList.size()
                && Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.CERTINFO_TAG),
                "Certificate container: tag 71 must immediately follow tag 70");
    }
    
	//Tag 0x72 is optionally present and follows tags from 73-4.19
    @DisplayName("SP800-73-4.20 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_20(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = o.getTagList();
		
		BerTag berCertTag = new BerTag(TagConstants.CERTIFICATE_TAG);
		BerTag berMSCUIDTag = new BerTag(TagConstants.MSCUID_TAG);
		
		if(tagList.contains(berMSCUIDTag)) {
			
			int tagIndex = tagList.indexOf(berCertTag);
			
			assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.CERTIFICATE_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.CERTINFO_TAG));
			assertTrue(Arrays.equals(tagList.get(tagIndex+2).bytes,TagConstants.MSCUID_TAG));
		}		       
        
    }

    // SP 800-73-5 Part 1 Appendix A Tables 11 and 16-18 remove MSCUID
    // from the four active PIV certificate containers. Retired containers
    // remain governed by Tables 21-40 and the historical atom above.
    @DisplayName("SP800-73-5 active certificate MSCUID test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    @ResultReference(publication = "SP 800-73-5 Part 1",
            location = "Appendix A, Tables 11 and 16 through 18, pp. 36 through 38",
            url = "https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final",
            documentUrl = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf#page=48",
            excerpt = "Note that the MSCUID data element has been eliminated in this version.",
            scope = "Checks that MSCUID (72) is absent from active certificate containers. Retired certificates have different rules.")
    void sp800_73_5_Test_20(String oid, TestReporter reporter) {
        if (AtomHelper.isOptionalAndAbsent(oid)) {
            return;
        }
        List<BerTag> tags = AtomHelper.getDataObject(oid).getTagList();
        assertFalse(tags.contains(new BerTag(TagConstants.MSCUID_TAG)),
                "SP800-73-5 X509: MSCUID tag 0x72 is not permitted in an active certificate container");
    }
    
	//Tag 0xFE is present and follows tags from 73-4.19, 73-4.20
    @DisplayName("SP800-73-4.21 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_21(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = o.getTagList();
		
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

    @DisplayName("SP800-73-5 active certificate FE order test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    @ResultReference(publication = "SP 800-73-5 Part 1",
            location = "Appendix A opening, p. 33; Tables 11 and 16 through 18, pp. 36 through 38",
            url = "https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final",
            documentUrl = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf#page=45",
            excerpt = "For each container, compliant cards SHALL return all TLV elements of the container in the order listed in this appendix.",
            scope = "Checks that Error Detection Code (FE) immediately follows CertInfo (71) in an active certificate container.")
    void sp800_73_5_Test_21(String oid, TestReporter reporter) {
        if (AtomHelper.isOptionalAndAbsent(oid)) {
            return;
        }
        List<BerTag> tags = AtomHelper.getDataObject(oid).getTagList();
        int certInfo = tags.indexOf(new BerTag(TagConstants.CERTINFO_TAG));
        assertTrue(certInfo >= 0 && certInfo + 1 < tags.size()
                && tags.get(certInfo + 1).equals(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG)),
                "SP800-73-5 X509: tag 0xFE must immediately follow tag 0x71");
    }
    
	//No tags other than (0x70, 0x71, 0x72, 0xFE) are present
    @DisplayName("SP800-73-4.22 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_22(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        
		List<BerTag> tagList = o.getTagList();
		
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

    @DisplayName("SP800-73-5 active certificate allowed tags test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    @ResultReference(publication = "SP 800-73-5 Part 1",
            location = "Appendix A, Tables 11 and 16 through 18 (tag columns), pp. 36 through 38",
            url = "https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final",
            documentUrl = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf#page=48",
            excerpt = "Certificate 0x70\nCertInfo 0x71\nError Detection Code 0xFE",
            scope = "Allows only Certificate (70), CertInfo (71) and Error Detection Code (FE) in active certificate containers. This rule does not cover retired containers.")
    void sp800_73_5_Test_22(String oid, TestReporter reporter) {
        if (AtomHelper.isOptionalAndAbsent(oid)) {
            return;
        }
        List<BerTag> tags = AtomHelper.getDataObject(oid).getTagList();
        for (BerTag tag : tags) {
            assertTrue(tag.equals(new BerTag(TagConstants.CERTIFICATE_TAG))
                    || tag.equals(new BerTag(TagConstants.CERTINFO_TAG))
                    || tag.equals(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG)),
                    "SP800-73-5 X509: only tags 0x70, 0x71, and 0xFE are permitted");
        }
    }

    
	//Confirm that tag 0xFE has length of 0
    @DisplayName("SP800-73-4.23 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_x509TestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_23(String oid, TestReporter reporter) {
		if (AtomHelper.isOptionalAndAbsent(oid))
			return;
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		assertNotNull(o, "Required container is absent: " + oid);
        
        
		List<BerTag> tagList = o.getTagList();
		
		BerTag berEDCTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		assertTrue(tagList.contains(berEDCTag));

		boolean ecHasData =  o.getErrorDetectionCodeHasData();
		
		assertTrue(ecHasData == false);
    }
    
    @SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_x509TestProvider() {
    	
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
}
