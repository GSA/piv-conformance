package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;

import gov.gsa.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.conformancelib.utilities.AtomHelper;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.DiscoveryObject;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.TagConstants;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SP800_73_4DiscoveryObjectTests {
	

    private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4DiscoveryObjectTests.class);

	//Discovery Object blob no larger than 19 bytes
	@DisplayName("SP800-73-4.38 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_38(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);

		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		//Check blob length
		assertTrue(bertlv.length <= 20);
		
		assertTrue(bertlv[bertlv.length-1] == 0x00);
	}

	//Tag 0x4F is present
	@DisplayName("SP800-73-4.40 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_40(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((DiscoveryObject) o).getTagList();		
		BerTag cardAppAIDTag = new BerTag(TagConstants.PIV_CARD_APPLICATION_AID_TAG);

		//Confirm Tag 0x4F is present
		assertTrue(tagList.contains(cardAppAIDTag));	
	}
	
	// Tag 0x5F2F is present
	@DisplayName("SP800-73-4.41 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_41(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((DiscoveryObject) o).getTagList();
		
		BerTag pinUsagePolicyTag = new BerTag(TagConstants.PIN_USAGE_POLICY_TAG);

		assertTrue(tagList.contains(pinUsagePolicyTag));			
	}
	
	//Discovery Object The PIN usage policy matches the card capabilities provided by the vendor documentation. 
	//Associated optional data objects are present when the PIN usage policy asserts an optional capability (i.e., OCC, global PIN and pairing code)
	@DisplayName("SP800-73-4.42 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_42(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		boolean globalPINisPrimary = ((DiscoveryObject) o).globalPINisPrimary();
		
		if(globalPINisPrimary) {
			s_logger.info("Global PIN is the primary PIN used to satisfy the PIV ACRs for command execution and object access.");

			try {
				CardUtils.authenticateInSingleton(true);
			} catch (ConformanceTestException e) {
				fail(e);
			}
		} else {
			s_logger.info("PIV Card Application PIN is the primary PIN used to satisfy the PIV ACRs for command execution and object access.");

			try {
				CardUtils.authenticateInSingleton(false);
			} catch (ConformanceTestException e) {
				fail(e);
			}
		}
			
	}
	
	// Tags 0x4F, 0x5F2F are in that order (split from 73-4.40)
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	@DisplayName("SP800-73-4.55 test")
	void sp800_73_4_Test_55 (String oid, TestReporter reporter) {
				
		PIVDataObject o = AtomHelper.getDataObject(oid);
		
		List<BerTag> tagList = ((DiscoveryObject) o).getTagList();
		
		BerTag cardAppAIDTag = new BerTag(TagConstants.PIV_CARD_APPLICATION_AID_TAG);
		
		int tagIndex = tagList.indexOf(cardAppAIDTag);
		
		//Confirm (0x4F, 0x5F2F) tag order
		assertTrue(Arrays.equals(tagList.get(tagIndex).bytes,TagConstants.PIV_CARD_APPLICATION_AID_TAG));
		assertTrue(Arrays.equals(tagList.get(tagIndex+1).bytes,TagConstants.PIN_USAGE_POLICY_TAG));
	}
	
	// this is now only used to test changes to the atoms
	private static Stream<Arguments> sp800_73_4_DiscoveryObjectTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.DISCOVERY_OBJECT_OID));

	}

}
