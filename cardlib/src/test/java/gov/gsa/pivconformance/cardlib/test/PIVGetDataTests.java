package gov.gsa.pivconformance.cardlib.test;

import gov.gsa.pivconformance.cardlib.card.client.APDUConstants;
import gov.gsa.pivconformance.cardlib.card.client.ApplicationAID;
import gov.gsa.pivconformance.cardlib.card.client.ApplicationProperties;
import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.cardlib.card.client.ConnectionDescription;
import gov.gsa.pivconformance.cardlib.card.client.DefaultPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVAuthenticators;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.cardlib.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.cardlib.card.client.PIVMiddleware;
import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.api.TestInfo;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag("Hardware")
public class PIVGetDataTests {
    List<CardTerminal> terminals = null;
    DefaultPIVApplication piv = null;
    String applicationPin = null;
    @BeforeEach
    void init(TestInfo testInfo) {
        applicationPin = HardwareTestCredentials.pinFor(testInfo);
        PCSCUtils.ConfigureUserProperties();
        TerminalFactory tf = TerminalFactory.getDefault();
        try {
            terminals = tf.terminals().list();
        } catch (CardException e) {
            fail("Unable to list readers");
        }
        assertTrue(!terminals.isEmpty(), "No PC/SC reader is available");
    }

    @Test
    @DisplayName("Ensure readers")
    void testReaderList() {
        assertTrue(!terminals.isEmpty(), "No PC/SC reader is available");
    }

    @Test
    @DisplayName("Test connection")
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

    @Test
    @DisplayName("Test app selection")
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
        piv = new DefaultPIVApplication();
        ApplicationAID aid  = new ApplicationAID();
        ApplicationProperties cardAppProperties = new ApplicationProperties();
        result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
        assertEquals(MiddlewareStatus.PIV_OK, result);
    }

    @Test
    @Tag("PIN")
    @DisplayName("Test authentication")
    void testAuth(TestReporter reporter) {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        try {
            assertTrue(terminals.get(0).isCardPresent(), "No card is inserted");
        }catch(CardException ce) {
            fail(ce);
        }
        CardHandle ch = new CardHandle();
        MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
        assertEquals(MiddlewareStatus.PIV_OK, result);
        piv = new DefaultPIVApplication();
        ApplicationAID aid  = new ApplicationAID();
        ApplicationProperties cardAppProperties = new ApplicationProperties();
        result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
        assertEquals(MiddlewareStatus.PIV_OK, result);
        PIVAuthenticators authenticators = new PIVAuthenticators();
        authenticators.addApplicationPin(applicationPin);
        result = piv.pivLogIntoCardApplication(ch, authenticators.getBytes());
        assertEquals(MiddlewareStatus.PIV_OK, result);
    }

    @Test
    @Tag("PIN")
    @DisplayName("Test pivGetData")
    void testPIVGetData(TestReporter reporter) {
        ConnectionDescription cd = ConnectionDescription.createFromTerminal(terminals.get(0));
        try {
            assertTrue(terminals.get(0).isCardPresent(), "No card is inserted");
        }catch(CardException ce) {
            fail(ce);
        }
        CardHandle ch = new CardHandle();
        MiddlewareStatus result = PIVMiddleware.pivConnect(true, cd, ch);
        assertEquals(MiddlewareStatus.PIV_OK, result);
        piv = new DefaultPIVApplication();
        ApplicationAID aid  = new ApplicationAID();
        ApplicationProperties cardAppProperties = new ApplicationProperties();
        result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
        assertEquals(MiddlewareStatus.PIV_OK, result);
        PIVAuthenticators authenticators = new PIVAuthenticators();
        authenticators.addApplicationPin(applicationPin);
        result = piv.pivLogIntoCardApplication(ch, authenticators.getBytes());
        assertEquals(MiddlewareStatus.PIV_OK, result);

        for(String containerOID : APDUConstants.MandatoryContainers()) {
            PIVDataObject dataObject = PIVDataObjectFactory.createDataObjectForOid(containerOID);

            result = piv.pivGetData(ch, containerOID, dataObject);
            assertEquals(MiddlewareStatus.PIV_OK, result);
        }
    }
}
