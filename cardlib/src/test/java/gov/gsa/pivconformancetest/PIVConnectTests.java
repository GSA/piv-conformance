package gov.gsa.pivconformancetest;

import gov.gsa.pivconformance.card.client.*;
import org.junit.BeforeClass;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @Test @DisplayName("Test connection")
    void testConnection() {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        try {
            assert (terminals.get(0).isCardPresent());
        }catch(CardException ce) {
            fail(ce);
        }
        CardHandle ch = new CardHandle();
        MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
        assert(result == MiddlewareStatus.PIV_OK);
    }

    @Test @DisplayName("Test app selection")
    void testSelect(TestReporter reporter) {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        try {
            assert (terminals.get(0).isCardPresent());
        }catch(CardException ce) {
            fail(ce);
        }
        CardHandle ch = new CardHandle();
        MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
        assertEquals(result, MiddlewareStatus.PIV_OK);
        reporter.publishEntry("Reader", cd.getTerminal().getName());
        DefaultPIVApplication piv = new DefaultPIVApplication();
        ApplicationAID aid  = new ApplicationAID();
        ApplicationProperties cardAppProperties = new ApplicationProperties();
        result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
        assertEquals(MiddlewareStatus.PIV_OK, result);
    }
}
