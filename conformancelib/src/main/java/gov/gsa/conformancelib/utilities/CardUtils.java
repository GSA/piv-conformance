package gov.gsa.conformancelib.utilities;

import java.util.List;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.conformancelib.tests.ConformanceTestException;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.ApplicationAID;
import gov.gsa.pivconformance.card.client.ApplicationProperties;
import gov.gsa.pivconformance.card.client.CachingDefaultPIVApplication;
import gov.gsa.pivconformance.card.client.CardHandle;
import gov.gsa.pivconformance.card.client.ConnectionDescription;
import gov.gsa.pivconformance.card.client.DefaultPIVApplication;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVAuthenticators;
import gov.gsa.pivconformance.card.client.PIVMiddleware;
import gov.gsa.pivconformance.utils.PCSCUtils;

public class CardUtils {
	static {
		PCSCUtils.ConfigureUserProperties();
	}
	public static void setUpReaderInSingleton() throws ConformanceTestException {
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardTerminal reader = null;
		int idx = css.getReaderIndex();
		// just use the first terminal
		List<String> readers = PCSCUtils.GetConnectedReaders();
		if(readers.isEmpty()) {
			throw new ConformanceTestException("No connected readers found");
		}
		if(idx > readers.size()) {
			throw new ConformanceTestException("Reader index specified: " + idx + " but only " + readers.size() + " connected.");
		}
		if(idx == -1) {				
			reader = PCSCUtils.TerminalForReaderName(readers.get(0));
		} else {
			reader = PCSCUtils.TerminalForReaderName(readers.get(idx));
		}
		if(reader == null) {
			throw new ConformanceTestException("Unable to connect to card reader");
		}
		css.setTerminal(reader);
		
	}
	
	// this method will set up the card and piv application handles in the singleton according to the reader index if specified
	public static boolean setUpPivAppHandleInSingleton() throws ConformanceTestException {
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardTerminal reader = css.getTerminal();
		if(reader == null) {
			setUpReaderInSingleton();
			reader = css.getTerminal();
		}
		try {
			if(reader == null || !reader.isCardPresent()) {
				throw new ConformanceTestException("No card is present");
			}
		} catch (CardException e) {
			throw new ConformanceTestException("Failed to detect card presence", e);
		}
		CardHandle ch = css.getCardHandle();
		if(ch == null) {
			ConnectionDescription cd = ConnectionDescription.createFromTerminal(reader);
			ch = new CardHandle();
			MiddlewareStatus connectResult = PIVMiddleware.pivConnect(false, cd, ch);
			if(connectResult != MiddlewareStatus.PIV_OK) {
				throw new ConformanceTestException("pivConnect() failed: " + connectResult);
			}
			css.setCardHandle(ch); css.setPivHandle(null);
			DefaultPIVApplication piv = new CachingDefaultPIVApplication();
			ApplicationProperties cardAppProperties = new ApplicationProperties();
			ApplicationAID aid = new ApplicationAID();
			connectResult = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
			if(connectResult != MiddlewareStatus.PIV_OK) {
				throw new ConformanceTestException("pivSelectCardApplication() failed");
			}
			css.setPivHandle(piv);
		}
		return true;
	}
	
	// this method will authenticate to the card
	public static boolean authenticateInSingleton(boolean useGlobal ) throws ConformanceTestException {
		
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		
		PIVAuthenticators authenticators = new PIVAuthenticators();
		
		if (css.getLastLoginStatus() != LOGIN_STATUS.LOGIN_SUCCESS) {
		
			if(useGlobal) {
				
				if(css.getGlobalPin() == null || css.getGlobalPin().length() == 0) {
					css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
					throw new ConformanceTestException("authenticateInSingleton() failed, missing global pin");
				}
								
				authenticators.addApplicationPin(css.getGlobalPin());			
			} else {
				
				if(css.getApplicationPin() == null || css.getApplicationPin().length() == 0) {
					css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
					throw new ConformanceTestException("authenticateInSingleton() failed, missing application pin");
				}
				
				authenticators.addApplicationPin(css.getApplicationPin());
			}
			
	        //Get card handle and PIV handle
	        CardHandle ch = css.getCardHandle();
	        AbstractPIVApplication piv = css.getPivHandle();
	        
	        MiddlewareStatus result = piv.pivLogIntoCardApplication(ch, authenticators.getBytes());
	        if(MiddlewareStatus.PIV_OK != result){
	        	css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
				throw new ConformanceTestException("authenticateInSingleton() failed");
			}
		} 

        // Cache the last login status status here, not inside the if block, guarantees
		// worst case is that a security requirement is not met.
        
        css.setLastLoginStatus(LOGIN_STATUS.LOGIN_SUCCESS);
        
        return true;
	}	
}
