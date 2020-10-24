package gov.gsa.pivconformance.conformancelib.tests;

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
import gov.gsa.pivconformance.cardlib.card.client.DiscoveryObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.cardlib.tlv.BerTag;
import gov.gsa.pivconformance.cardlib.tlv.TagConstants;


public class SP800_73_4DiscoveryObjectTests {
	
    private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4DiscoveryObjectTests.class);

	//Discovery Object Max Bytes comply with Table 18 in SP 800-83-4
	@DisplayName("SP800-73-4.38 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_DiscoveryObjectTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_38(String oid, TestReporter reporter) {		
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
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_DiscoveryObjectTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.DISCOVERY_OBJECT_OID));

	}

}
