
package gov.gsa.pivconformance.card.gp;

import javax.smartcardio.ResponseAPDU;

/**
 * Exception class for GPSC errors
 */
@SuppressWarnings("serial")
public class GPSCException extends Exception {

    /**
     * Response status indicating the error, or 0 if not applicable.
     */
    public final int sw;

    public GPSCException(int sw, String message) {
        super(message + ": " + GPSCData.sw2str(sw));
        this.sw = sw;
    }

    public GPSCException(String message) {
        super(message);
        this.sw = 0x0000;
    }

    public GPSCException(String message, Throwable e) {
        super(message, e);
        this.sw = 0x0000;
    }

    public static ResponseAPDU check(ResponseAPDU response, String message, int... sws) throws GPSCException {
        for (int sw : sws) {
            if (response.getSW() == sw) {
                return response;
            }
        }
        // Fallback
        if (response.getSW() == 0x9000) {
            return response;
        }

        throw new GPSCException(response.getSW(), message);
    }

    public static ResponseAPDU check(ResponseAPDU response) throws GPSCException {
        return check(response, "GPSC failed");
    }
}
