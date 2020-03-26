package gov.gsa.conformancelib.tests;

// Uncomment when needed
import static org.junit.Assert.assertTrue;
// import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.fail;

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
import gov.gsa.pivconformance.card.client.PIVDataObject;

/**
 * This class is a collector that allows maintainers to collapse like atoms
 * and reduce code maintenance.
 * :1,$s/56/57/g
 * 
 * 10-step data-driven design approach to code reduction:
 * 
 * 1. Add 1 to this number right here: [ 56 ]
 * 2. On the Steps Overview tab of the .xlsx sheet, locate the two rows with atoms that perform the same function and 
 *    change the description to <match the description of the atoms>. Change the atom to: 73-4.56. Change them to
 * 3. To the .csv file corresponding to the SP800-73-4 tab of the .xlsx sheet, import (append) a row with these values:
 * "73-4.56","gov.gsa.conformancelib.tests.SP800_73_4CommmonObjectTests","sp800_73_4_Test_56","<The test description>","<unit tested? (Yes/No)>"
 * 4. Copy the template method at the top of this class, pasting it at the end. 	
 * 5. Merge the two atoms. Fewer assertions is better so long as the main assertion does the intended assertion.
 * 6. Copy and paste the inside of the merged atom into method sp800_73_4_Test_56(). If the method already 
 *    uses AtomHelper, just overwrite the template method.
 * 7. JUnit test and comment test fixture code within
 * 8. To prove out that the collapse works:
 *    a. refactor collapsed methods, then rebuild and/or adjust database (parameterize, if necessary), and 
 *    repeat Step 7 and 8 until the two old test cases fails and the new case passes per the requirement. The trick
 *    is make the test runner fail with a graceful popup at runtime or a Python KeyError: '73-4.xx' during mk_db.sh
 *    until correctly merged. 
 * 9. On the SP800-73-4 tab, locate the old atom rows, removed them, save, and rebuild the database. The next test
 *    should run with no unexpected failures and no popups. If either occurs, investigate, fix, and repeat 7-9.
 * 10. The old atoms can be removed from the appropriate test class and the system can be rebuilt.
 * 
 *
 */

public class SP800_73_4CommmonObjectTests {
    private static final Logger s_logger = LoggerFactory.getLogger(SP800_73_4CommmonObjectTests.class);
    // <cut>
    //
    // Template methods
    //
	// <assert NIST Special Publications 800-73-4 here - this example collapses *just the length check* of 
    // the tags in each cert>
    @DisplayName("SP800-73-4.56 test")
    @ParameterizedTest(name = "{index} => oid = {0}")
    // @MethodSource("sp800_73_4CommonObjectsTestProvider")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void sp800_73_4_Test_56(String oid, TestReporter reporter) {
    	// TODO: Since this could be caught, longer-term, consider Throwable
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
		
		assertTrue(true); // or switch to assertTrue(false) for a fall-through test if coded that way
    }
    @SuppressWarnings("unused")
	private static Stream<Arguments> sp800_73_4CommonObjectsTestProvider() {
    	// Just an example - be stream of any APDUConstants.<anyOid>
    	return Stream.of(
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID),
                Arguments.of(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID)
                );

    }
    // </cut>
}
