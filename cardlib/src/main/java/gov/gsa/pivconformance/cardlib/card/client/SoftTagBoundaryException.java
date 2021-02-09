package gov.gsa.pivconformance.cardlib.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class for non-fatal tag boundary exceptions
 */
public class SoftTagBoundaryException extends Exception {
    private static final Logger s_logger = LoggerFactory.getLogger(SoftTagBoundaryException.class);

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

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
