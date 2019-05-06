package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import java.util.Arrays;
import java.util.Date;
import java.util.Calendar;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_73_4CHUIDTests {

	//CHUID blob no larger than 3395 bytes
	@DisplayName("SP800-73-4.8 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_8(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		assertTrue(bertlv.length <= 3395);
	}

	//If CHUID tag 0xEE is present, it is the first tag in the blob
	@DisplayName("SP800-73-4.9 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_9(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((CardHolderUniqueIdentifier) o).getTagList();
		
		BerTag berBufferLenTagTag = new BerTag(TagConstants.BUFFER_LENGTH_TAG);
		if(tagList.contains(berBufferLenTagTag))
		{
			assertTrue(Arrays.equals(tagList.get(0).bytes,TagConstants.BUFFER_LENGTH_TAG));
		}
    }

	//Tag 0x30 is present and is the first tag or the first tag following 0xEE
	@DisplayName("SP800-73-4.10 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_10(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((CardHolderUniqueIdentifier) o).getTagList();
		
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
		assertTrue(tagList.contains(berFASCTag));
		
		int tagIndex = tagList.indexOf(berFASCTag);
		
		assertTrue(tagIndex == 0 || tagIndex == 1);
			
	}
	
	//Tags 0x32 and 0x33 are optionally present and must follow 0x30 in that order
	@DisplayName("SP800-73-4.11 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_11(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((CardHolderUniqueIdentifier) o).getTagList();
		
		BerTag berOrgIDTag = new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG);
		BerTag berDUNSTag = new BerTag(TagConstants.DUNS_TAG);
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
		
		if(tagList.contains(berOrgIDTag)) {

			int orgIDTagIndex = tagList.indexOf(berFASCTag);
			
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.FASC_N_TAG));
			assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
		}
		
		
		if(tagList.contains(berDUNSTag)) {

			int orgIDTagIndex = tagList.indexOf(berFASCTag);	

			if(tagList.contains(berOrgIDTag)) {
				
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+2).bytes,TagConstants.DUNS_TAG));
			
			} else {
			
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgIDTagIndex+1).bytes,TagConstants.DUNS_TAG));				
			
			}
		}
		
		
	}
	
	//Tags 0x34 and 0x35 are present and follow tags from 73-4.10, 73-4.11
	@DisplayName("SP800-73-4.12 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_12(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((CardHolderUniqueIdentifier) o).getTagList();
		
		BerTag berOrgIDTag = new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG);
		BerTag berDUNSTag = new BerTag(TagConstants.DUNS_TAG);
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
		BerTag berGUIDTag = new BerTag(TagConstants.GUID_TAG);
		BerTag berExpirationDateTag = new BerTag(TagConstants.CHUID_EXPIRATION_DATE_TAG);
		
		
		
		assertTrue(tagList.contains(berGUIDTag) && tagList.contains(berExpirationDateTag)); 
		
		assertTrue(tagList.size() >= 3);
		
		int orgFASCNTagIndex = tagList.indexOf(berFASCTag);
		assertTrue(orgFASCNTagIndex >= 0);
		
		boolean optionalTagsPresent = false;
		
		if(tagList.contains(berOrgIDTag)) {

			optionalTagsPresent = true;			
			assertTrue(tagList.size() >= 4);
			
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.GUID_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
		}
		
		
		if(tagList.contains(berDUNSTag)) {

			optionalTagsPresent = true;

			if(tagList.contains(berOrgIDTag)) {
				
				assertTrue(tagList.size() >= 5);
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.DUNS_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.GUID_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
			
			} else {
			
				assertTrue(tagList.size() >= 4);
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.DUNS_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.GUID_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));				
			
			}
		}
		
		if(optionalTagsPresent == false) {
			
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.GUID_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
			
		}
		
		
	}
	
	//Tag 0x36 is optionally present and follows tags from 73-4.10, 73-4.11, 73-4.12
	@DisplayName("SP800-73-4.13 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_13(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((CardHolderUniqueIdentifier) o).getTagList();
		
		BerTag berOrgIDTag = new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG);
		BerTag berDUNSTag = new BerTag(TagConstants.DUNS_TAG);
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
		BerTag berCardholderUUIDTag = new BerTag(TagConstants.CARDHOLDER_UUID_TAG);
		
		
		
		if(tagList.contains(berCardholderUUIDTag)) {
			
			assertTrue(tagList.size() >= 4);
			
			int orgFASCNTagIndex = tagList.indexOf(berFASCTag);
			assertTrue(orgFASCNTagIndex >= 0);
			
			boolean optionalTagsPresent = false;
			
			if(tagList.contains(berOrgIDTag)) {
	
				optionalTagsPresent = true;			
				assertTrue(tagList.size() >= 5);
				
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.GUID_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.CARDHOLDER_UUID_TAG));
			}
			
			if(tagList.contains(berDUNSTag)) {
	
				optionalTagsPresent = true;
	
				if(tagList.contains(berOrgIDTag)) {
					
					assertTrue(tagList.size() >= 6);
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.DUNS_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.GUID_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+5).bytes,TagConstants.CARDHOLDER_UUID_TAG));
				
				} else {
				
					assertTrue(tagList.size() >= 5);
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.DUNS_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.GUID_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
					assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.CARDHOLDER_UUID_TAG));				
				
				}
			}
			
			if(optionalTagsPresent == false) {
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.GUID_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CARDHOLDER_UUID_TAG));
				
			}	
		}
	}
	
	//Tags 0x3E and 0xFE are present and follow tags from 73-4.10, 73-4.11, 73-4.12, 73-4.13 in that order
	@DisplayName("SP800-73-4.14 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_14(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((CardHolderUniqueIdentifier) o).getTagList();
		
		BerTag berOrgIDTag = new BerTag(TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG);
		BerTag berDUNSTag = new BerTag(TagConstants.DUNS_TAG);
		BerTag berFASCTag = new BerTag(TagConstants.FASC_N_TAG);
		BerTag berIssuerAssymSigTag = new BerTag(TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG);
		BerTag berErrorDetectionCodeTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
			
		assertTrue(tagList.contains(berIssuerAssymSigTag) && tagList.contains(berErrorDetectionCodeTag)); 
			
		assertTrue(tagList.size() >= 6);
		
		int orgFASCNTagIndex = tagList.indexOf(berFASCTag);
		assertTrue(orgFASCNTagIndex >= 0);
		
		boolean optionalTagsPresent = false;
		
		if(tagList.contains(berOrgIDTag)) {

			optionalTagsPresent = true;			
			assertTrue(tagList.size() >= 7);
			
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.GUID_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.CARDHOLDER_UUID_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+5).bytes,TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+6).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
		}
		
		if(tagList.contains(berDUNSTag)) {

			optionalTagsPresent = true;

			if(tagList.contains(berOrgIDTag)) {
				
				assertTrue(tagList.size() >= 8);
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.ORGANIZATIONAL_IDENTIFIER_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.DUNS_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.GUID_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+5).bytes,TagConstants.CARDHOLDER_UUID_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+6).bytes,TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+7).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
			
			} else {
			
				assertTrue(tagList.size() >= 7);
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.DUNS_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.GUID_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.CARDHOLDER_UUID_TAG));	
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+5).bytes,TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG));
				assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+6).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));			
			
			}
		}
		
		if(optionalTagsPresent == false) {
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex).bytes,TagConstants.FASC_N_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+1).bytes,TagConstants.GUID_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+2).bytes,TagConstants.CHUID_EXPIRATION_DATE_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+3).bytes,TagConstants.CARDHOLDER_UUID_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+4).bytes,TagConstants.ISSUER_ASYMMETRIC_SIGNATURE_TAG));
			assertTrue(Arrays.equals(tagList.get(orgFASCNTagIndex+5).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
			
		}	
		
	}
	
	//Expiration Date is formatted YYYYMMDD
	@DisplayName("SP800-73-4.15 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_15(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		Date expirationDate = ((CardHolderUniqueIdentifier) o).getExpirationDate();
		
		//Decode for CardHolderUniqueIdentifier class parses the date in YYYYMMDD format.
		assertNotNull(expirationDate);
		

    }
	
	//Expiration Date is with in 5 years
	@DisplayName("SP800-73-4.16 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider2")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_16(String oid, String yearsStr, TestReporter reporter) {
        
		//Check that the yearsStr passed in is not null
		if (yearsStr == null) {
			ConformanceTestException e  = new ConformanceTestException("OID is null");
			fail(e);
		}
        
		int years = 0;
		try {
			years = Integer.parseInt(yearsStr);
		} catch(NumberFormatException e) {
			fail(e);
		}
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		Date expirationDate = ((CardHolderUniqueIdentifier) o).getExpirationDate();
		
		Calendar cal = Calendar.getInstance();
		Date today = cal.getTime();
		cal.add(Calendar.YEAR, years); 
		Date todayPlus5Years = cal.getTime();
		
		assertTrue(expirationDate.compareTo(today) >= 0);
		assertTrue(expirationDate.compareTo(todayPlus5Years) <= 0);
		

    }
	
	//No tags other than (0xEE, 0x30, 0x32, 0x33, 0x34, 0x35, 0x36, 0x3E, 0xFE) are present
	@DisplayName("SP800-73-4.17 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_17(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
				
		List<BerTag> tagList = ((CardHolderUniqueIdentifier) o).getTagList();
		
		List<byte[]> allCHUIDTags = TagConstants.AllCHUIDTags();
		for(BerTag tag : tagList) {

			//Check that the tag is present in the all CCC tags list
			boolean present = false;
			for (int i = 0; i < allCHUIDTags.size(); i++) {
				
				if(Arrays.equals(allCHUIDTags.get(i), tag.bytes)) {
					present = true;
					break;
				}
			}
			assertTrue(present);
		}
    }
	
	// Tag 0x30 is the first tag or the first tag following 0xEE (split from 73-4.10)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.43 test")
	void sp800_73_4_Test_43 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
	
	// Tag 0x34 is present (split from 73-4.12)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.44 test")
	void sp800_73_4_Test_44 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
    
    // Tag 0x34 follows Tag 0x30, 32, or 0x33
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.45 test")
	void sp800_73_4_Test_45 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
    
	// Tag 0x35 is present (split from 73-4.12)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.46 test")
	void sp800_73_4_Test_46 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
       
	// Tag 0x35 follows Tag 0x34 (split from 73-4.12)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.47 test")
	void sp800_73_4_Test_47 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
	
	// Tag 0x3E is present (split from 73-4.14)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.48 test")
	void sp800_73_4_Test_48 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
 	
    // Tag 0x3E follows Tag 0x35 or 0x36 (split from 73-4.14)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.49 test")
	void sp800_73_4_Test_49 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
 	
	// Tag 0xFE is present (split from 73-4.14)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.49 test")
	void sp800_73_4_Test_50 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}

	// Tag 0xFE follows Tag 0x3E (split from 73-4.14)
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_CHUIDTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.51 test")
	void sp800_73_4_Test_51 (String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		// The first of up to 2 allowed assertions
		assertTrue(o.decode(), "Couldn't decode " + oid);
		
		// TODO: Assert something meaningful here
		assertTrue(o.getBytes().length >= 0, "Length is < 0");
	}
    
	private static Stream<Arguments> sp800_73_4_CHUIDTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID));

	}
	
	private static Stream<Arguments> sp800_73_4_CHUIDTestProvider2() {

		return Stream.of(Arguments.of(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, "14"));

	}

}
