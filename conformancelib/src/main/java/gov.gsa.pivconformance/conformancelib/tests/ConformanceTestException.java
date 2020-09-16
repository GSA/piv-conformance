package gov.gsa.pivconformance.conformancelib.tests;

public class ConformanceTestException extends Exception {
	public ConformanceTestException() { super(); }
	public ConformanceTestException(String message) {
		super(message);
	}
	public ConformanceTestException(String message, Throwable cause) {
		super(message, cause);
	}

	private static final long serialVersionUID = -4140820929950230L;

}
