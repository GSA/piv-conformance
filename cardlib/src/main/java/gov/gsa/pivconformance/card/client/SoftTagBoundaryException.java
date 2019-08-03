package gov.gsa.pivconformance.card.client;

/**
 * A class for card-related exceptions
 */
public class SoftTagBoundaryException extends Exception {

	/**
	 *
	 * Default constructor for CardClientException class
	 *
	 */
	public SoftTagBoundaryException() {
		super();
	}

	/**
	 *
	 * Constructor for CardClientException class that takes a string with exception
	 * message
	 *
	 * @param message String with the exception message
	 */
	public SoftTagBoundaryException(String message) {
		super(message);
	}

	/**
	 *
	 * Constructor for CardClientException class that takes a string with exception
	 * message and a Throwable cause
	 *
	 * @param message String with the exception message
	 * @param cause   Throwable cause
	 */
	public SoftTagBoundaryException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 *
	 * Constructor for CardClientException class that takes a Throwable cause
	 *
	 * @param cause Throwable cause
	 */
	public SoftTagBoundaryException(Throwable cause) {
		super(cause);
	}
}
