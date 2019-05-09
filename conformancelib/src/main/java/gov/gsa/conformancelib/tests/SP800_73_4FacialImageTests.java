package gov.gsa.conformancelib.tests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

public class SP800_73_4FacialImageTests {

	//Card Holder Facial Image blob no larger than 12710 bytes
	@DisplayName("SP800-73-4.32 test")
	@ParameterizedTest(name = "{index} => oid = {0}")
	//@MethodSource("sp800_73_4_FacialImageTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
	void sp800_73_4_Test_32(String oid, TestReporter reporter) {
		
		PIVDataObject o = AtomHelper.getDataObjectWithAuth(oid);
		byte[] bertlv = o.getBytes();
		assertNotNull(bertlv);

		//Check Card Holder Facial Image blob length
		assertTrue(bertlv.length <= 12710);
	}

	
	// this is only used to test the atom now... it is no longer operative in the conformance tester
	@SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4_FacialImageTestProvider() {

		return Stream.of(Arguments.of(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID));

	}

}
