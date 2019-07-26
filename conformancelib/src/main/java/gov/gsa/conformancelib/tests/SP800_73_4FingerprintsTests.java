package gov.gsa.conformancelib.tests;

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

import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.CardholderBiometricData;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

public class SP800_73_4FingerprintsTests {
    private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4FingerprintsTests.class);

	//Fingerprints container blob no larger than 4006 bytes
	@DisplayName("SP800-73-4.24 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_FingerprintsTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_24(String oid, TestReporter reporter) {
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

	//Tags 0xBC and 0xFE are present in that order
	@DisplayName("SP800-73-4.25 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    //@MethodSource("sp800_73_4_FingerprintsTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_25(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
		
		List<BerTag> tagList = ((CardholderBiometricData) o).getTagList();
		
		BerTag berFingerprintTag = new BerTag(TagConstants.FINGERPRINT_I_AND_II_TAG);
		BerTag berECTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		//Confirm (0xBC, 0xFE) are present 
		assertTrue(tagList.contains(berFingerprintTag));
		assertTrue(tagList.contains(berECTag));
		
		int tagIndex = tagList.indexOf(berFingerprintTag);
		
		//Confirm (0xBC, 0xFE) tag order
		assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.FINGERPRINT_I_AND_II_TAG));
		assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.ERROR_DETECTION_CODE_TAG));

    }

	//No tags other than (0xBC, 0xFE) are present
	@DisplayName("SP800-73-4.26 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_FingerprintsTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_26(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
		
		List<BerTag> tagList = ((CardholderBiometricData) o).getTagList();
		
		BerTag berFingerprintTag = new BerTag(TagConstants.FINGERPRINT_I_AND_II_TAG);
		BerTag berECTag = new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG);
		
		//Confirm only two tags are present
		assertTrue(tagList.size() == 2);
		
		//Confirm (0xBC, 0xFE) are present 
		assertTrue(tagList.contains(berFingerprintTag));
		assertTrue(tagList.contains(berECTag));
			
	}
	

	// this is only used to test the atom now... it is no longer operative in the conformance tester
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_FingerprintsTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FINGERPRINTS_OID));

	}

}
