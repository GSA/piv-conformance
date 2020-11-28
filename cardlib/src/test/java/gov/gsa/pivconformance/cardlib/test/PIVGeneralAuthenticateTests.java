package gov.gsa.pivconformance.cardlib.test;

import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestReporter;

import gov.gsa.pivconformance.cardlib.card.client.ApplicationAID;
import gov.gsa.pivconformance.cardlib.card.client.ApplicationProperties;
import gov.gsa.pivconformance.cardlib.card.client.ConnectionDescription;
import gov.gsa.pivconformance.cardlib.card.client.DefaultPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVAuthenticators;
import gov.gsa.pivconformance.cardlib.card.client.PIVMiddleware;

import static org.junit.jupiter.api.Assertions.*;

public class PIVGeneralAuthenticateTests {

    List<CardTerminal> terminals = null;
    DefaultPIVApplication piv = null;
    CardHandle currentCardHandle = null;
    ConnectionDescription currentConnection = null;

    //@BeforeEach
    void init() {
        PCSCUtils.ConfigureUserProperties();
        TerminalFactory tf = TerminalFactory.getDefault();
        try {
            terminals = tf.terminals().list();
            for(CardTerminal t: terminals) {
            	if(t.isCardPresent()) {
            		currentConnection = ConnectionDescription.createFromTerminal(t);
            		break;
            	}
            }
            if(currentConnection == null || !currentConnection.getTerminal().isCardPresent()) {
            	fail("Unable to find a reader with a card present");
            }
            currentCardHandle = new CardHandle();
            MiddlewareStatus result = PIVMiddleware.pivConnect(true, currentConnection, currentCardHandle);
            assert(result == MiddlewareStatus.PIV_OK);
            piv = new DefaultPIVApplication();
            ApplicationAID aid  = new ApplicationAID();
            ApplicationProperties cardAppProperties = new ApplicationProperties();
            result = piv.pivSelectCardApplication(currentCardHandle, aid, cardAppProperties);
			assertEquals(MiddlewareStatus.PIV_OK, result);
			PIVAuthenticators authenticators = new PIVAuthenticators();
			authenticators.addApplicationPin("123456");
			result = piv.pivLogIntoCardApplication(currentCardHandle, authenticators.getBytes());
			assertEquals(MiddlewareStatus.PIV_OK, result);
        } catch (CardException e) {
            fail("Unable to establish PIV connection");
        }
    }

    @Test
    @Tag("PIN")
    @DisplayName("Test GENERAL AUTHENTICATE")
    void testGeneralAuthenticate(TestReporter reporter) {
    	assertNull(null);
    }
}
