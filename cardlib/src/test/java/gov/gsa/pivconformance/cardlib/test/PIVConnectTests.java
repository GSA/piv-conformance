package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.ApplicationAID;
import gov.gsa.pivconformance.cardlib.card.client.ApplicationProperties;
import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.cardlib.card.client.ConnectionDescription;
import gov.gsa.pivconformance.cardlib.card.client.DefaultPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVMiddleware;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestReporter;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("Hardware")
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
        assertTrue(!terminals.isEmpty(), "No PC/SC reader is available");
    }

    @Test @DisplayName("Ensure readers")
    void testReaderList() {
        assertTrue(!terminals.isEmpty(), "No PC/SC reader is available");
    }

    @Test @DisplayName("Test reader descriptor")
    void testConnectionDescription() {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        assertNotNull(cd);
        byte[] cdbytes = cd.getBytes();
        assertTrue(cdbytes.length > 1);
    }

    @Test @DisplayName("Test connection")
    void testConnection() {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        try {
            assertTrue(terminals.get(0).isCardPresent(), "No card is inserted");
        }catch(CardException ce) {
            fail(ce);
        }
        CardHandle ch = new CardHandle();
        MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
        assertEquals(MiddlewareStatus.PIV_OK, result);
    }

    @Test @DisplayName("Test app selection")
    void testSelect(TestReporter reporter) {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        try {
            assertTrue(terminals.get(0).isCardPresent(), "No card is inserted");
        }catch(CardException ce) {
            fail(ce);
        }
        CardHandle ch = new CardHandle();
        MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
        assertEquals(MiddlewareStatus.PIV_OK, result);
        reporter.publishEntry("Reader", cd.getTerminal().getName());
        DefaultPIVApplication piv = new DefaultPIVApplication();
        ApplicationAID aid  = new ApplicationAID();
        ApplicationProperties cardAppProperties = new ApplicationProperties();
        result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
        assertEquals(MiddlewareStatus.PIV_OK, result);
    }
}
