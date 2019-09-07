package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.CardCapabilityContainer;
import gov.gsa.pivconformance.card.client.CardHolderUniqueIdentifier;
import gov.gsa.pivconformance.card.client.CardHolderBiometricData;
import gov.gsa.pivconformance.card.client.DiscoveryObject;
import gov.gsa.pivconformance.card.client.KeyHistoryObject;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PrintedInformation;
import gov.gsa.pivconformance.card.client.SecurityObject;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_73_4SecurityObjectTests {
	static Logger s_logger = LoggerFactory.getLogger(SP800_73_4SecurityObjectTests.class);

	//Security Object value lengths comply with Table 12 of SP 800-73-4
	@DisplayName("SP800-73-4.33 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_33(String oid, TestReporter reporter) {
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
		//Confirm Security object blob is not larger than 120
		// assertTrue(bertlv.length <= 1008); // TODO: https://github.com/GSA/piv-conformance/issues/90
	}

	//Tags 0xBA, 0xBB, 0XFE are present
	@DisplayName("SP800-73-4.34 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_34(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		// Get tag list
		List<BerTag> tagList = ((SecurityObject) o).getTagList();
		
		BerTag berMappingTag = new BerTag(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG);
		BerTag berSecurityObjectTag = new BerTag(TagConstants.SECURITY_OBJECT_TAG);
		BerTag berEDCTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		// Confirm tags 0xBA, 0xBB, 0XFE are present
		assertTrue(tagList.contains(berMappingTag));
		assertTrue(tagList.contains(berSecurityObjectTag));
		assertTrue(tagList.contains(berEDCTag));
		
    }
	
	//No tags other than (0xBA, 0xBB, 0xFE) are present
	@DisplayName("SP800-73-4.35 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_35(String oid, TestReporter reporter) {
		String logTag = "SP800-73-4.35: " + oid;

		PIVDataObject o = AtomHelper.getDataObject(oid);

		// Get tag list
		List<BerTag> tagList = ((SecurityObject) o).getTagList();
		
		BerTag berMappingTag = new BerTag(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG);
		BerTag berSecurityObjectTag = new BerTag(TagConstants.SECURITY_OBJECT_TAG);
		BerTag berEDCTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		for(BerTag t : tagList) {
			s_logger.debug("{}: got tag {}", logTag, t.toString());
		}
		
		// Confirm tags 0x01, 0x02, 0x05, 0x06 are present
		assertTrue(tagList.contains(berMappingTag));
		assertTrue(tagList.contains(berSecurityObjectTag));
		assertTrue(tagList.contains(berEDCTag));
		
		
		// Confirm only 3 tags are present
		assertTrue(tagList.size() == 3);
		
		int orgMappingTagIndex = tagList.indexOf(berMappingTag);
		
		// Confirm tags 0x01, 0x02, 0x05, 0x06 are in right order
		assertTrue(Arrays.equals(tagList.get(orgMappingTagIndex).bytes,TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG));
		assertTrue(Arrays.equals(tagList.get(orgMappingTagIndex+1).bytes,TagConstants.SECURITY_OBJECT_TAG));
		assertTrue(Arrays.equals(tagList.get(orgMappingTagIndex+2).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
    }
	
	//Parse data at tag 0xBA and for each data container found ensure that performing a select returns status words 0x90, 0x00
	@DisplayName("SP800-73-4.36 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_36(String oid, TestReporter reporter) {

		PIVDataObject o = AtomHelper.getDataObject(oid);

        boolean decoded = o.decode();
		assertTrue(decoded);
		
		HashMap<Integer, String> idList = ((SecurityObject) o).getContainerIDList();
		
		assertTrue(idList.size() > 0);
		
		for (HashMap.Entry<Integer,String> entry : idList.entrySet())  {
		
            System.out.println("Key = " + entry.getKey() + ", Value = " + entry.getValue()); 

            PIVDataObject tmpObj = AtomHelper.getDataObject(entry.getValue());
            assertNotNull(tmpObj);;
		}
    }
	
	//For each container listed in the security object, calculate the hash of the data within that container and confirm that the actual 
	//hashes match those written to the security object
	@DisplayName("SP800-73-4.37 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_37(String oid, TestReporter reporter) {

		// this was parameterized but only tests the security object
		// default to that to address Issue #141 until we confirm that nothing expects to pass an oid
		// in and just change the signature
		PIVDataObject o = null;
		
		if((oid == null) || oid.isEmpty()) {
			o = AtomHelper.getDataObject(APDUConstants.SECURITY_OBJECT_OID);
		} else {
			// a log message to help confirm no other uses of this parameter that were unexpected
			o = AtomHelper.getDataObject(oid);
			s_logger.warn("SP800-73-4.37 was called with an OID of {}. Confirm that this is correct on the spreadsheet.", oid);
		}
        
        boolean decoded = o.decode();
		assertTrue(decoded);
		
		HashMap<String, byte[]> soDataElements = new  HashMap<String, byte[]>();
		
		HashMap<Integer, String> idList = ((SecurityObject) o).getContainerIDList();
		
		assertTrue(idList.size() > 0);
		
		for (HashMap.Entry<Integer,String> entry : idList.entrySet())  {
            System.out.println("Key = " + entry.getKey() + ", Value = " + entry.getValue()); 
            s_logger.debug("[Security object: 0x{} about to read {} from card", Integer.toHexString(entry.getKey()), entry.getValue());
            PIVDataObject dataObject = AtomHelper.getDataObject(entry.getValue());
            
            decoded = dataObject.decode();
    		assertTrue(decoded);
            
            if(entry.getValue().equals(APDUConstants.CARD_CAPABILITY_CONTAINER_OID)) {
        		soDataElements.put(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, ((CardCapabilityContainer) dataObject).getSignedContent());
            } else if(entry.getValue().equals(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID)) {
        		soDataElements.put(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID, ((CardHolderUniqueIdentifier) dataObject).getChuidContainer());            	
            } else if(entry.getValue().equals(APDUConstants.CARDHOLDER_FINGERPRINTS_OID)) {
        		soDataElements.put(APDUConstants.CARDHOLDER_FINGERPRINTS_OID, ((CardHolderBiometricData) dataObject).getCbeffContainer());           	
            } else if(entry.getValue().equals(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID)) {
        		soDataElements.put(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID, ((CardHolderBiometricData) dataObject).getCbeffContainer());        	
            } else if(entry.getValue().equals(APDUConstants.PRINTED_INFORMATION_OID)) {
        		soDataElements.put(APDUConstants.PRINTED_INFORMATION_OID, ((PrintedInformation) dataObject).getSignedContent());       	
            } else if(entry.getValue().equals(APDUConstants.DISCOVERY_OBJECT_OID)) {
        		soDataElements.put(APDUConstants.DISCOVERY_OBJECT_OID, ((DiscoveryObject) dataObject).getSignedContent());       	
            } else if(entry.getValue().equals(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID)) {
        		soDataElements.put(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID, ((CardHolderBiometricData) dataObject).getCbeffContainer());        	
            } else if(entry.getValue().equals(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID)) {
        		soDataElements.put(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID, ((CardHolderBiometricData) dataObject).getCbeffContainer());
            } else if(entry.getValue().equals(APDUConstants.KEY_HISTORY_OBJECT_OID)) {
            	s_logger.debug("Adding key history to soDataElements");
            	soDataElements.put(APDUConstants.KEY_HISTORY_OBJECT_OID, ((KeyHistoryObject) dataObject).getTlvBuf());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_1_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_2_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_3_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_4_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_5_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_6_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_7_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_8_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_9_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_10_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_11_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_12_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_13_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_14_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_15_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_16_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_17_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_18_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_19_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID)) {
                soDataElements.put(APDUConstants.RETIRED_X_509_CERTIFICATE_FOR_KEY_MANAGEMENT_20_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID)) {
                soDataElements.put(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID)) {
                soDataElements.put(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID)) {
                soDataElements.put(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID, dataObject.getBytes());
            } else if(entry.getValue().equals(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID)) {
                soDataElements.put(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID, dataObject.getBytes());             
            }  else {
            	fail("Unrecongnized container OID (" + oid + ")");
            }
		}

		((SecurityObject) o).setMapOfDataElements(soDataElements);
		
		//Confirm that message digest from signed attributes bag matches the digest over Fingerprint biometric data (excluding contents of digital signature field) 
		boolean verified = ((SecurityObject) o).verifyHashes();
		assertTrue(verified);
    }

	//Tags 0xBA, 0xBB, 0XFE are in that order
	@DisplayName("SP800-73-4.54 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_SecurityObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_54(String oid, TestReporter reporter) {
		try {
			PIVDataObject o = AtomHelper.getDataObject(oid);
	        
	        boolean decoded = o.decode();
			assertTrue(decoded);
			
			// Get tag list
			List<BerTag> tagList = ((SecurityObject) o).getTagList();
			
			BerTag berMappingTag = new BerTag(TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG);
			BerTag berSecurityObjectTag = new BerTag(TagConstants.SECURITY_OBJECT_TAG);
			BerTag berEDCTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
			
			// Confirm tags 0xBA, 0xBB, 0XFE are present
			if (tagList.contains(berMappingTag) == false) {
				Exception e = new Exception("MAPPING_OF_DG_TO_CONTAINER_ID_TAG is missing");
				throw e;
			}
			if (tagList.contains(berSecurityObjectTag) == false) {
				Exception e = new Exception("SECURITY_OBJECT_TAG is missing");
				throw e;
			}
			if (tagList.contains(berEDCTag) == false) {
				Exception e = new Exception("ERROR_DETECTION_CODE_TAG is missing");
				throw e;
			}
			
			int orgMappingTagIndex = tagList.indexOf(berMappingTag);
			
			// Confirm tags 0xBA, 0xBB, 0XFE are in right order
			assertTrue(Arrays.equals(tagList.get(orgMappingTagIndex).bytes,TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG));
			assertTrue(Arrays.equals(tagList.get(orgMappingTagIndex+1).bytes,TagConstants.SECURITY_OBJECT_TAG));
			assertTrue(Arrays.equals(tagList.get(orgMappingTagIndex+2).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));
		}
		catch (Exception e) {
			fail(e);
		}
	}
	
	// this is only used to test the atom now... it is no longer operative in the conformance tester
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_SecurityObjectTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.SECURITY_OBJECT_OID));
	}
}
