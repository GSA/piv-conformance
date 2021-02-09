package gov.gsa.pivconformance.cardlib.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class for container tag boundary exceptions
 */
public class TagBoundaryException extends Exception {
    private static final Logger s_logger = LoggerFactory.getLogger(TagBoundaryException.class);
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 *
	 * Default constructor for TagBoundaryException class
	 *
	 */
	public TagBoundaryException() {
		super();
	}

	/**
	 *
	 * Constructor for TagBoundaryException class that takes a string with exception
	 * message
	 *
	 * @param message String with the exception message
	 */
	public TagBoundaryException(String message) {
		super(message);
	}

	/**
	 *
	 * Constructor for TagBoundaryException class that takes a string with exception
	 * message and a Throwable cause
	 *
	 * @param message String with the exception message
	 * @param cause   Throwable cause
	 */
	public TagBoundaryException(String message, Throwable cause) {
		super(message, cause);
	}

	/**
	 *
	 * Constructor for TagBoundaryException class that takes a Throwable cause
	 *
	 * @param cause Throwable cause
	 */
	public TagBoundaryException(Throwable cause) {
		super(cause);
	}
}
