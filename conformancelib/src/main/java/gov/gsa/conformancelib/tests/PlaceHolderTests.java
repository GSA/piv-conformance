package gov.gsa.conformancelib.tests;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;

public class PlaceHolderTests {

	public PlaceHolderTests() {
	}

	@Test @DisplayName("DeadBeef.1 Test")
	void DeadBeef_1(TestReporter reporter) {
		assertNotNull(null);
	}
}
