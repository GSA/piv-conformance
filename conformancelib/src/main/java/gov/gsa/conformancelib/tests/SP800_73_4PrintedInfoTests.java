package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PrintedInformation;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_73_4PrintedInfoTests {

	//Printed Information blob is no larger than 120 bytes
	@DisplayName("SP800-73-4.27 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_27(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv, "No data returned from PIVDataObject");

		//was: Confirm blob is not larger than 120
		// see issue #72
		assertTrue(bertlv.length <= 245, "Printed object length must be no larger than 245 bytes: got " + bertlv.length);
	}

	//Tags 0x01, 0x02, 0x05, 0x06 are present
	@DisplayName("SP800-73-4.28 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_28(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
		
		//Get tag list
		List<BerTag> tagList = ((PrintedInformation) o).getTagList();
		
		BerTag berNameTag = new BerTag(TagConstants.NAME_TAG);
		BerTag berEmployeeAffiliationTag = new BerTag(TagConstants.EMPLOYEE_AFFILIATION_TAG);
		BerTag berPrintedInformationExpirationDateTag = new BerTag(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG);
		BerTag berAgencyCardSerialTag = new BerTag(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG);
		BerTag berIssuerIDTag = new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG);
		
		//Confirm tags 0x01, 0x02, 0x05, 0x06 are present
		assertTrue(tagList.contains(berNameTag));
		assertTrue(tagList.contains(berEmployeeAffiliationTag));
		assertTrue(tagList.contains(berPrintedInformationExpirationDateTag));
		assertTrue(tagList.contains(berAgencyCardSerialTag));
		assertTrue(tagList.contains(berIssuerIDTag));
    }
	
	//Tags 0x07 and 0x08 are optionally present in that order, following the tags from 73-4.28
	@DisplayName("SP800-73-4.29 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_PrintedInfoTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_29(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
		
		List<BerTag> tagList = ((PrintedInformation) o).getTagList();
		
		BerTag berNameTag = new BerTag(TagConstants.NAME_TAG);
		BerTag berIssuerIdTag = new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG);
		BerTag berOrgAffiliationTag = new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L1_TAG);
		BerTag berOrgAffiliationL2Tag = new BerTag(TagConstants.ORGANIZATIONAL_AFFILIATION_L2_TAG);
		
		//Make sure Name tage is present
		assertTrue(tagList.contains(berNameTag));
		
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
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
		
		List<BerTag> tagList = ((PrintedInformation) o).getTagList();
		
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
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
				
		List<BerTag> tagList = ((PrintedInformation) o).getTagList();
		
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
			PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
			
			//Get tag list
			List<BerTag> tagList = ((PrintedInformation) o).getTagList();
			
			BerTag berNameTag = new BerTag(TagConstants.NAME_TAG);
			BerTag berEmployeeAffiliationTag = new BerTag(TagConstants.EMPLOYEE_AFFILIATION_TAG);
			BerTag berPrintedInformationExpirationDateTag = new BerTag(TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG);
			BerTag berAgencyCardSerialTag = new BerTag(TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG);
			BerTag berIssuerIDTag = new BerTag(TagConstants.ISSUER_IDENTIFICATION_TAG);
			
			//Confirm tags 0x01, 0x02, 0x05, 0x06 are present
			if (tagList.contains(berNameTag) == false){
				Exception e = new Exception("NAME_TAG is missing in tagList");
				throw e;
			}
			if (tagList.contains(berEmployeeAffiliationTag) == false) {
				Exception e = new Exception("EMPLOYEE_AFFILIATION_TAG is missing in tagList");
				throw e;
			}
			if (tagList.contains(berPrintedInformationExpirationDateTag) == false) {
				Exception e = new Exception("PRINTED_INFORMATION_EXPIRATION_DATE_TAG is missing in tagList");
				throw e;
			}
			if (tagList.contains(berAgencyCardSerialTag) == false) {
				Exception e = new Exception("AGENCY_CARD_SERIAL_NUMBER_TAG is missing in tagList");
				throw e;
			}
			if (tagList.contains(berIssuerIDTag) == false) {
				Exception e = new Exception("ISSUER_IDENTIFICATION_TAG is missing in tagList");
				throw e;
			}
			
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
			
			/*
			//Confirm tags 0x01, 0x02, 0x05, 0x06 are in right order
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.NAME_TAG));
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.EMPLOYEE_AFFILIATION_TAG));
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+2).bytes,TagConstants.PRINTED_INFORMATION_EXPIRATION_DATE_TAG));
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+3).bytes,TagConstants.AGENCY_CARD_SERIAL_NUMBER_TAG));
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+4).bytes,TagConstants.ISSUER_IDENTIFICATION_TAG));
			*/
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
			PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
			
			List<BerTag> tagList = ((PrintedInformation) o).getTagList();
			
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
