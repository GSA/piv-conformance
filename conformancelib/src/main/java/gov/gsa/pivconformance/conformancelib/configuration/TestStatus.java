package gov.gsa.pivconformance.conformancelib.configuration;

import java.util.Arrays;
import java.util.Optional;

public enum TestStatus {

	TESTCATEGORY(-2),
	NONE(-1),
	FAIL(0),
	PASS(1),
	SKIP(2);

	private final int value;

	TestStatus(int value) {
		this.value = value;
	}
	
	public static Optional<TestStatus> valueOf(int value) {
        return Arrays.stream(values())
            .filter(status -> status.value == value)
            .findFirst();
    }
	
	public int getValue() {
		return value;
	}

}