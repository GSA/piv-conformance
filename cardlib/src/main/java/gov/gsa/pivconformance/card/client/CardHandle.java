package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;

/**
 * A class that serves the function of the handle objects passed around that encapsulate a connection to a card
 * in SP800-73
 */
public class CardHandle {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(CardHandle.class);

    /**
     * Get the connection description object associated with this card handle
     * @return ConnectionDescription that includes as CardTerminal object used to access the reader
     */
    public ConnectionDescription getConnectionDescription() {
        return m_connectionDescription;
    }

    /**
     * set the connection description object that will be used by the card handle
     * @param connectionDescription Connection description object
     */
    public void setConnectionDescription(ConnectionDescription connectionDescription) {
        m_connectionDescription = connectionDescription;
    }

    /**
     *
     * Set the Card object that will be used by the card handle
     *
     * @param card Card object
     */
    public void setCard(Card card) {
        m_card = card;
    }

    /**
     *
     * Get the Card object associated with this card handle
     *
     * @return Card object
     */
    public Card getCard() {
        return m_card;
    }

    /**
     * Initialize an invalid card handle object
     */
    public CardHandle() {
        m_connectionDescription = null;
        m_card = null;
        m_currentChannel = null;
        m_valid = false;
    }

    /**
     *
     * Get the current card channel
     *
     * @return CardChannel object
     */
    public CardChannel getCurrentChannel() {
        return m_currentChannel;
    }

    /**
     *
     * Sets the current card channel
     *
     * @param currentChannel CardChannel object
     */
    public void setCurrentChannel(CardChannel currentChannel) {
        m_currentChannel = currentChannel;
    }

    /**
     *
     * Returns trues if card handle is valid for accessing a PIV card
     *
     * @return true if the handle is valid for accessing a PIV card
     */
    public boolean isValid() {
        return m_valid;
    }

    /**
     *
     * Sets the value that indicates the status of the card handle object
     *
     * sets the boolen value that indicates the status of card handle object
     * @param valid
     */
    public void setValid(boolean valid) {
        m_valid = valid;
    }

    private ConnectionDescription m_connectionDescription;
    private boolean m_valid = false;
    private Card m_card;


    private CardChannel m_currentChannel;

}
