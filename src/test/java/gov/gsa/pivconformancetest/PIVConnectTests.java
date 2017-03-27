package gov.gsa.pivconformancetest;

import gov.gsa.pivconformance.card.client.ConnectionDescription;
import org.junit.BeforeClass;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.util.List;

import static org.junit.jupiter.api.Assertions.fail;

public class PIVConnectTests {
    List<CardTerminal> terminals = null;
    @BeforeEach
    void init() {
        TerminalFactory tf = TerminalFactory.getDefault();
        try {
            terminals = tf.terminals().list();
        } catch (CardException e) {
            fail("Unable to list readers");
        }
    }

    @Test @DisplayName("Ensure readers")
    void testReaderList() {
        assert(terminals.size() > 0);
    }

    @Test @DisplayName("Test reader descriptor")
    void testConnectionDescription() {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        assert(cd != null);
        byte[] cdbytes = cd.getBytes();
        assert(cdbytes.length > 1);
    }
}
