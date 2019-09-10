package gov.gsa.pivconformance.card.client;

/**
 * A base class for exceptions thrown by PIV application methods
 */
public class PIVApplicationException extends Exception {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
     *
     * Default constructor for PIVApplicationException class
     *
     */
    public PIVApplicationException() {
        super();
    }

    /**
     *
     * Constructor for PIVApplicationException class that takes a string with exception message
     *
     * @param message String with the exception message
     */
    public PIVApplicationException(String message) {
        super(message);
    }

    /**
     *
     * Constructor for PIVApplicationException class that takes a string with exception message and a Throwable cause
     *
     * @param message String with the exception message
     * @param cause Throwable cause
     */
    public PIVApplicationException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     *
     * Constructor for PIVApplicationException class that takes a Throwable cause
     *
     * @param cause Throwable cause
     */
    public PIVApplicationException(Throwable cause) {
        super(cause);
    }
}
