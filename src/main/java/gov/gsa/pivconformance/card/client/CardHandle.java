package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A class that serves the function of the handle objects passed around that encapsulate a connection to a card
 * in SP800-73
 */
public class CardHandle {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardHandle.class);

    /**
     * get the connection description object associated with this card handle
     * @return ConnectionDescription that includes as CardTerminal object used to access the reader
     */
    public ConnectionDescription getConnectionDescription() {
        return m_connectionDescription;
    }

    /**
     * set the connection description object that will be used by the card handle
     * @param connectionDescription
     */
    public void setConnectionDescription(ConnectionDescription connectionDescription) {
        m_connectionDescription = connectionDescription;
    }

    /**
     * Initialize an invalid card handle object
     */
    public CardHandle() {
        m_connectionDescription = null;
        m_valid = false;
    }

    /**
     *
     * @return true if the handle is valid for accessing a PIV card
     */
    public boolean isValid() {
        return m_valid;
    }

    private ConnectionDescription m_connectionDescription;
    private boolean m_valid = false;

}
