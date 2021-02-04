package gov.gsa.pivconformance.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

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
import gov.gsa.pivconformance.cardlib.card.client.PrintedInformation;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.cardlib.tlv.BerTag;
import gov.gsa.pivconformance.cardlib.tlv.TagConstants;

public class SP800_73_4PrintedInfoTests {
    private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4PrintedInfoTests.class);

	//Printed Information value lengths comply with Table 14 of SP 800-73-4
	@DisplayName("SP800-73-4.27 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_27(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);	
			if (!o.inBounds(oid)) {
				String errStr = (String.format("Tag in " + o.getFriendlyName() + " failed length check"));
				Exception e = new Exception(errStr);
				throw(e);
			}
		} catch (Exception e) {
			s_logger.info(e.getMessage());
			fail(e);
		}
	}

	//Tags 0x01, 0x02, 0x05, 0x06 are present
	@DisplayName("SP800-73-4.28 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_28(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		//Get tag list
		List<BerTag> tagList = o.getTagList();
		
		BerTag berNameTag = new BerTag(TagConstants.NAME_TAG);
		BerTag berEmployeeAffiliationTag = new BerTag(TagConstants.EMPLOYEE_AFFILIATION_TAG);
		BerTag berPrintedInformationExpirationDateTag = new BerTag(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG);
		BerTag berAgencyCardSerialTag = new BerTag(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG);
		BerTag berIssuerIDTag = new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG);
		
		//Confirm tags 0x01, 0x02, 0x05, 0x06 are present
		assertTrue(tagList.contains(berNameTag), "Container does not include Name");
		assertTrue(tagList.contains(berEmployeeAffiliationTag), "Container does not include Employee Affiliation");
		assertTrue(tagList.contains(berPrintedInformationExpirationDateTag), "Container does not include Expiration Date");
		assertTrue(tagList.contains(berAgencyCardSerialTag), "Container does not include Agency Card Serial Number");
		assertTrue(tagList.contains(berIssuerIDTag), "Container does not include Issuer Identifier");
    }
	
	//Tags 0x07 and 0x08 are optionally present in that order, following the tags from 73-4.28
	@DisplayName("SP800-73-4.29 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_29(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = o.getTagList();
		
		BerTag berIssuerIdTag = new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG);
		BerTag berOrgAffiliationTag = new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG);
		BerTag berOrgAffiliationL2Tag = new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG);

		//If organizational affiliation tag is present check the order
		
		if(tagList.contains(berOrgAffiliationTag)) {
			int issuerIdTagIndex = tagList.indexOf(berIssuerIdTag);	
			assertFalse(issuerIdTagIndex == -1, "Issuer Identification tag must be present");
			int orgAffiliationTagIndex = tagList.indexOf(berOrgAffiliationTag);
			assertTrue(orgAffiliationTagIndex == issuerIdTagIndex + 1, "Tag 0x07 must follow tag 0x06 if present");
			int orgAffiliationTagL2Index = tagList.indexOf(berOrgAffiliationL2Tag);
			if(orgAffiliationTagL2Index != -1) {
				assertTrue(orgAffiliationTagL2Index == orgAffiliationTagIndex + 1, "Tag 0x08 must follow tag 0x07 if present");
			}
		} else {
			assertFalse(tagList.contains(berOrgAffiliationL2Tag));
		}
	}
	
	//Tag 0xFE is present
	@DisplayName("SP800-73-4.30 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_30(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = o.getTagList();
		
		BerTag berECTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		//Make sure EDC tag is present
		assertTrue(tagList.contains(berECTag));
	}
	
	//No tags other than (0x01, 0x02, 0x05, 0x06, 0x07, 0x08, 0xFE) are present
	@DisplayName("SP800-73-4.31 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_31(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
				
		List<BerTag> tagList = o.getTagList();
		
		List<byte[]> allPrintedInfoTags = TagConstants.AllPrintedInfoTags();
		for(BerTag tag : tagList) {

			//Check that the tag is present in the all Printed Information tags list
			boolean present = false;
			for (int i = 0; i < allPrintedInfoTags.size(); i++) {
				
				if(Arrays.equals(allPrintedInfoTags.get(i), tag.bytes)) {
					present = true;
					break;
				}
			}
			assertTrue(present);
			
		}
	}
		
	// Tags 0x01, 0x02, 0x05, 0x06 are in that order (split from 73-4.28)
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.52 test")
	void sp800_73_4_Test_52 (String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			//Get tag list
			List<BerTag> tagList = o.getTagList();
			
			BerTag berNameTag = new BerTag(TagConstants.NAME_TAG);
			BerTag berEmployeeAffiliationTag = new BerTag(TagConstants.EMPLOYEE_AFFILIATION_TAG);
			BerTag berPrintedInformationExpirationDateTag = new BerTag(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG);
			BerTag berAgencyCardSerialTag = new BerTag(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG);
			BerTag berIssuerIDTag = new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG);
			// Moving to make assertions about the indexes so that this test does exactly what it says
			// in the description. I think based on my read of 73-4 appendix A what this was doing should be correct
			// but we should re-litigate that later if needed; the description as written makes no assertions about
			// the printed information expiration date tag and GSA PIVs follow the letter of the description in this case.
			int nameTagIndex = tagList.indexOf(berNameTag);
			int employeeAffiliationTagIndex = tagList.indexOf(berEmployeeAffiliationTag);
			int serialNumberTagIndex = tagList.indexOf(berAgencyCardSerialTag);
			int issuerIdTagIndex = tagList.indexOf(berIssuerIDTag);
			assertTrue(nameTagIndex < employeeAffiliationTagIndex, "Tag 0x02 must follow tag 0x01");
			assertTrue(employeeAffiliationTagIndex < serialNumberTagIndex , "Tag 0x05 must follow tag 0x02");
			assertTrue(serialNumberTagIndex < issuerIdTagIndex, "Tag 0x06 must follow tag 0x05");
		}
		catch (Exception e) {
			fail(e);
		}
	}

	// Tag 0xFE follows Tag 0x06, or optional Tags 0x07 or 0x08 (split from 73-4.30)
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.53 test")
	void sp800_73_4_Test_53 (String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
			
			List<BerTag> tagList = o.getTagList();
			
			BerTag berNameTag = new BerTag(TagConstants.NAME_TAG);
			BerTag berIssuerIdentificationTag = new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG);
			BerTag berOrgAffiliationTag = new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG);
			BerTag berOrgAffiliationL2Tag = new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG);
			BerTag berECTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
			
			//Make sure Name tag is present
			if (tagList.contains(berNameTag) == false) {
				Exception e = new Exception("NAME_TAG is missing");
				throw e;
			}
			//Get index of the name tag
			// int orgIDTagIndex = tagList.indexOf(berNameTag);
			
			
			//Make sure EDC tag is present
			if (tagList.contains(berECTag)==false) {
				Exception e = new Exception("ERROR_DETECTION_CODE_TAG is missing");
				throw e;
			}
			// Moving to make assertions about the indexes so that this test does exactly what it says
			// in the description. I think based on my read of 73-4 appendix A what this was doing should be correct
			// but we should re-litigate that later if needed; the description as written makes no assertions about
			// the printed information expiration date tag and GSA PIVs follow the letter of the description in this case.
			int ecTagIndex = tagList.indexOf(berECTag);
			assertTrue(ecTagIndex == tagList.size()-1, "ERROR_DETECTION_TAG must be the last tag");
			BerTag previousTag = tagList.get(ecTagIndex - 1);
			assertTrue(
					previousTag.equals(berOrgAffiliationL2Tag) ||
					previousTag.equals(berOrgAffiliationTag) ||
					previousTag.equals(berIssuerIdentificationTag),
					"Tag 0xFE must follow either tag 0x06, 0x07, 0x08."
					);
			
			
			/*
			boolean optionalPresent = false;
			
			//Check the order to make sure EDC tag is last
			if(tagList.contains(berOrgAffiliationTag)) {
				
				optionalPresent = true;
				
				//If organizational affiliation L2 tag is present check the order
				if(tagList.contains(berOrgAffiliationL2Tag)) {
					
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.NAME_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.EMPLOYEE_AFFILIATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+2).bytes,TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+3).bytes,TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+4).bytes,TagConstants.ISSUER_IDENTIFICATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+5).bytes,TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+6).bytes,TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+7).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
				
				} else {
				
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.NAME_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.EMPLOYEE_AFFILIATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+2).bytes,TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+3).bytes,TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+4).bytes,TagConstants.ISSUER_IDENTIFICATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+5).bytes,TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+6).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
				}
			}
			
			
			//If organizational affiliation L2 tag is present check the order
			if(tagList.contains(berOrgAffiliationL2Tag)) {
				
				optionalPresent = true;
	
				//Different conditions if organizational affiliation is also present 
				if(tagList.contains(berOrgAffiliationTag)) {
					
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.NAME_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.EMPLOYEE_AFFILIATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+2).bytes,TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+3).bytes,TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+4).bytes,TagConstants.ISSUER_IDENTIFICATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+5).bytes,TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+6).bytes,TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+7).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
				
				} else {
					
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.NAME_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.EMPLOYEE_AFFILIATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+2).bytes,TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+3).bytes,TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+4).bytes,TagConstants.ISSUER_IDENTIFICATION_TAG));
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+5).bytes,TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG));	
					assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+6).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));			
				
				}
			}
			
			//If no optional tags are present check the order
			if(optionalPresent == false) {
				
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.NAME_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.EMPLOYEE_AFFILIATION_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+2).bytes,TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+3).bytes,TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+4).bytes,TagConstants.ISSUER_IDENTIFICATION_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+5).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
			}*/
		}
		catch (Exception e) {
			fail(e);
		}
	}
	
	// this is only used to test the atom now... it is no longer operative in the conformance tester
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_PrintedInfoTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.PRINTED_INFORMATION_OID));

	}

}
