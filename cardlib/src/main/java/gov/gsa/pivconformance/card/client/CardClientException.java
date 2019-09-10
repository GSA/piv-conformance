package gov.gsa.pivconformance.card.client;

/**
 * A class for card-related exceptions
 */
public class CardClientException extends Exception {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
     *
     * Default constructor for CardClientException class
     *
     */
    public CardClientException() {
        super();
    }

    /**
     *
     * Constructor for CardClientException class that takes a string with exception message
     *
     * @param message String with the exception message
     */
    public CardClientException(String message) {
        super(message);
    }

    /**
     *
     * Constructor for CardClientException class that takes a string with exception message and a Throwable cause
     *
     * @param message String with the exception message
     * @param cause Throwable cause
     */
    public CardClientException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     *
     * Constructor for CardClientException class that takes a Throwable cause
     *
     * @param cause Throwable cause
     */
    public CardClientException(Throwable cause) {
        super(cause);
    }
}
