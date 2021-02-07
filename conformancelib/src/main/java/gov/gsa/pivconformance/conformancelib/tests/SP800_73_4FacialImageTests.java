package gov.gsa.pivconformance.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

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
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;

public class SP800_73_4FacialImageTests {
    private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4FacialImageTests.class);

	//Card Holder Facial Image blob no larger than 12710 bytes
	@DisplayName("SP800-73-4.32 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_FacialImageTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_32(String oid, TestReporter reporter) {
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

	
	// this is only used to test the atom now... it is no longer operative in the conformance tester
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_FacialImageTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID));

	}
}
