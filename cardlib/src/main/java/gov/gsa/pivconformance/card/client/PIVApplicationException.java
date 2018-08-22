package gov.gsa.pivconformance.card.client;

/**
 * A base class for exceptions thrown by PIV application methods
 */
public class PIVApplicationException extends Exception {
    public PIVApplicationException() {
        super();
    }

    public PIVApplicationException(String message) {
        super(message);
    }

    public PIVApplicationException(String message, Throwable cause) {
        super(message, cause);
    }

    public PIVApplicationException(Throwable cause) {
        super(cause);
    }
}
