package gov.gsa.conformancelib.configuration;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.pivconformance.card.client.ApplicationAID;
import gov.gsa.pivconformance.card.client.ApplicationProperties;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.ConnectionDescription;
import gov.gsa.pivconformance.card.client.DefaultPIVApplication;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVAuthenticators;
import gov.gsa.pivconformance.card.client.PIVMiddleware;
import gov.gsa.pivconformance.utils.PCSCUtils;

public class CardInfoController {
	private static final Logger s_logger = LoggerFactory.getLogger(CardInfoController.class);

	public static byte[] getATR()
	{
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardTerminal reader = css.getTerminal();
		if(reader == null) {
			s_logger.error("No card reader found.");
			return null;
		}
		try {
			if(!reader.isCardPresent()) {
				s_logger.error("No card is available in the selected reader");
				return null;
			}
		} catch (CardException e) {
			s_logger.error("Unable to communicate with card.", e);
			return null;
		}
		ConnectionDescription cd = ConnectionDescription.createFromTerminal(reader);
		CardHandle ch = css.getCardHandle();
		MiddlewareStatus result = PIVMiddleware.pivConnect(false, cd, ch);
		if(result != MiddlewareStatus.PIV_OK) {
			s_logger.error("PIV connection error");
			return null;
		}
		return ch.getCard().getATR().getBytes();
	}
	
	public static int getEncodedRetries()
	{
		int rv = -1;
		
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardTerminal reader = css.getTerminal();
		if(reader == null) {
			s_logger.error("No card reader found.");
			return -1;
		}
		
		try {
			if(!reader.isCardPresent()) {
				s_logger.error("No card present in {}", reader.getName());
				return -1;
			}
		} catch (CardException e) {
			s_logger.error("Exception when querying terminal for card", e);
			return -1;
		}
		
		ConnectionDescription cd = ConnectionDescription.createFromTerminal(reader);
		CardHandle ch = css.getCardHandle();
		MiddlewareStatus result = PIVMiddleware.pivConnect(false, cd, ch);

		try {
			if(result != MiddlewareStatus.PIV_OK)
				return -1;
			
			try {
				// Make sure we're logged out, as this call doesn't work if logged in
				ch.getCard().disconnect(true);
				result = PIVMiddleware.pivConnect(false, cd, ch);
			} catch (CardException e) {
				s_logger.debug("Attempt at card reset failed. Trying to proceed.");
			}
		
			DefaultPIVApplication piv = new DefaultPIVApplication();
	        ApplicationProperties cardAppProperties = new ApplicationProperties();
			ApplicationAID aid = new ApplicationAID();
			result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
			if(result != MiddlewareStatus.PIV_OK)
				return -1;
			
			PIVAuthenticators pivAuthenticators = new PIVAuthenticators();
			
			pivAuthenticators.addApplicationPin("");
			result = piv.pivLogIntoCardApplication(ch, pivAuthenticators.getBytes());
			if(result == MiddlewareStatus.PIV_AUTHENTICATION_FAILURE) {
				rv = (PCSCUtils.StatusWordsToRetries(piv.getLastResponseAPDUBytes()) & 0xf) << 4;
			}

			pivAuthenticators = new PIVAuthenticators();
			
			pivAuthenticators.addGlobalPin("");
			result = piv.pivLogIntoCardApplication(ch, pivAuthenticators.getBytes());
			if(result == MiddlewareStatus.PIV_AUTHENTICATION_FAILURE) {
				rv |= PCSCUtils.StatusWordsToRetries(piv.getLastResponseAPDUBytes()) & 0xf;
				s_logger.info("Global PIN: {} retries remain", rv);
			}
			return rv;
		} catch (Exception ex) {
			s_logger.error("Error: {}", ex.getLocalizedMessage());
		}
		return rv;
	}
	
	public static boolean checkPin(boolean useAppPin)
	{
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardTerminal reader = css.getTerminal();
		char[] pin;
		if(useAppPin) {
			pin = css.getApplicationPin().toCharArray();
		} else {
			pin = css.getGlobalPin().toCharArray();
		}
		if(reader == null) {
			s_logger.error("No card reader found.");
			return false;
		}
		
		try {
			if(!reader.isCardPresent()) {
				s_logger.error("No card present in {}", reader.getName());
				return false;
			}
		} catch (CardException e) {
			s_logger.error("Exception when querying terminal for card", e);
			return false;
		}
		PIVAuthenticators pivAuthenticators = new PIVAuthenticators();
		if (useAppPin) {
			pivAuthenticators.addApplicationPin(new String (pin));
		} else {
			pivAuthenticators.addGlobalPin(new String(pin));
		}

		ConnectionDescription cd = ConnectionDescription.createFromTerminal(reader);
		CardHandle ch = css.getCardHandle();
		MiddlewareStatus result = PIVMiddleware.pivConnect(false, cd, ch);
		if(result != MiddlewareStatus.PIV_OK) return false;
		DefaultPIVApplication piv = new DefaultPIVApplication();
        ApplicationProperties cardAppProperties = new ApplicationProperties();
		ApplicationAID aid = new ApplicationAID();
		result = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
		if(result != MiddlewareStatus.PIV_OK) return false;
		result = piv.pivLogIntoCardApplication(ch, pivAuthenticators.getBytes());
		if(result == MiddlewareStatus.PIV_AUTHENTICATION_FAILURE) {
			int tries = PCSCUtils.StatusWordsToRetries(piv.getLastResponseAPDUBytes());
			s_logger.info("Login failed. Application PIN: {} retries remain", tries);
			css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
			return false;
		}
		
		s_logger.info("Application PIN verified.");
		return true;
	}



}
