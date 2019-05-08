package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.utils.PCSCWrapper;

import javax.smartcardio.CardTerminal;
import javax.smartcardio.Card;


public class PIVMiddleware {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVMiddleware.class);
    public static final String PIV_MIDDLEWARE_VERSION = "800-73-4 Client API";

    /**
     * pivMiddlewareVersion from section 3.1.1 of SP 800-73-4
     *
     * @param version
     * @return PIV_OK if version was successfully retrieved
     */
    public static MiddlewareStatus pivMiddlewareVersion(PIVMiddlewareVersion version) {
        version.setVersion(PIV_MIDDLEWARE_VERSION);
        return MiddlewareStatus.PIV_OK;
    }

    /**
     * pivConnect from section 3.1.2 of SP 800-73-4
     *
     * @param sharedConnection
     * @param connectionDescription
     * @param cardHandle
     * @return PIV_OK if connection was successful, PIV_CONNECTION_DESCRIPTION_MALFORMED if an invalid ConnectionDescription object was passed in,
     * PIV_CONNECTION_FAILURE if no connection could be established, or PIV_CONNECTION_LOCKED if an exclusive connection was requested but another exclusive
     * connection to the card in the specified reader is already in progress.
     */
    public static MiddlewareStatus pivConnect(boolean sharedConnection, ConnectionDescription connectionDescription, CardHandle cardHandle) {

        // Need to figure out what to do with sharedConnection in context of JAVA
        CardTerminal t = connectionDescription.getTerminal();
        if(cardHandle == null)
            cardHandle = new CardHandle();

        if(connectionDescription.getTerminal() == null )
            return MiddlewareStatus.PIV_CONNECTION_DESCRIPTION_MALFORMED;

        try {
        	
        	PCSCWrapper pcsc = PCSCWrapper.getInstance();

            Card card = pcsc.connect(t);

            if(card != null) {
                cardHandle.setConnectionDescription(connectionDescription);
                cardHandle.setCard(card);
                cardHandle.setValid(true);
                cardHandle.setCurrentChannel(card.getBasicChannel());
            }

        }catch (Exception ex) {
            s_logger.error("Unable to establish connection to the card : ", ex.getMessage(), ex);
            return MiddlewareStatus.PIV_CONNECTION_FAILURE;
        }

        return MiddlewareStatus.PIV_OK;
    }

    /**
     * pivDisconnect from section 3.1.2 of SP 800-73-4
     *
     * @param cardHandle
     * @return PIV_OK if the connection was disconnected and the CardHandle invalidated, PIV_INVALID_CARD_HANDLE if cardHandle was invalid,
     * PIV_CARD_READER_ERROR if the connection could not be destroyed due to a reader failure.
     */
    public static MiddlewareStatus pivDisconnect(CardHandle cardHandle) {

        try {

            Card card = cardHandle.getCard();

            if(card == null || !cardHandle.isValid()) {
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;
            }

            //XXX Need to figure out if connections needs to be reset or not
            card.disconnect(false);
            //Invalidate cardHandle object
            cardHandle = new CardHandle();

        }catch (Exception ex) {

            s_logger.error("Unable to disconnect from the card : ", ex.getMessage());
            return MiddlewareStatus.PIV_CARD_READER_ERROR;
        }

        return MiddlewareStatus.PIV_OK;
    }
}
