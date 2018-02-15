package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardTerminal;

/**
 * Encapsulates a connection description data object (tag 0x7F21) as
 * defined by SP800-73-4 table 2
 */
public class ConnectionDescription {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ConnectionDescription.class);

    private CardTerminal m_reader;

    /**
     * Default c'tor is private - initialize using static factory methods.
     */
    private ConnectionDescription() {
    }

    public byte[] getBytes() {
        return null;
    }

    /**
     * Create a ConnectionDescription object from a javax.smartcardio.CardTerminal
     * @return ConnectionDescription used to interact with a PIV card in the specified terminal
     */
    public static ConnectionDescription createFromTerminal(CardTerminal reader) {
        ConnectionDescription rv = new ConnectionDescription();
        rv.m_reader = reader;
        return rv;
    }

    /**
     * Given the data object described in SP800-73-4 table 2, create a new connection description object
     */
    public static ConnectionDescription createFromBuffer(byte[] data) {
        return null;
    }

    /**
     * Get the reader that will be used to actually send/receive APDUs from the card
     * @return
     */
    public CardTerminal getTerminal() {
        return m_reader;
    }
}
