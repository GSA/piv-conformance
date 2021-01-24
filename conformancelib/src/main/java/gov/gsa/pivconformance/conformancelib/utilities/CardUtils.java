package gov.gsa.pivconformance.conformancelib.utilities;

import java.util.List;
import java.util.Scanner;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.cardlib.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.ApplicationAID;
import gov.gsa.pivconformance.cardlib.card.client.ApplicationProperties;
import gov.gsa.pivconformance.cardlib.card.client.CachingDefaultPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.cardlib.card.client.ConnectionDescription;
import gov.gsa.pivconformance.cardlib.card.client.DefaultPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.cardlib.card.client.PIVAuthenticators;
import gov.gsa.pivconformance.cardlib.card.client.PIVMiddleware;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton.LOGIN_STATUS;
import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import gov.gsa.pivconformance.cardlib.utils.PCSCUtils;

public class CardUtils {
	static Logger s_logger = LoggerFactory.getLogger(CardUtils.class);

	static {
		PCSCUtils.ConfigureUserProperties();
	}

	public static void setUpReaderInSingleton() throws ConformanceTestException {
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardTerminal reader = null;
		int idx = css.getReaderIndex();
		// just use the first terminal
		List<String> readers = PCSCUtils.GetConnectedReaders();
		if (readers.isEmpty()) {
			throw new ConformanceTestException("No connected readers found");
		}
		if (idx > readers.size()) {
			throw new ConformanceTestException(
					"Reader index specified: " + idx + " but only " + readers.size() + " connected.");
		}
		if (idx == -1) {
			reader = PCSCUtils.TerminalForReaderName(readers.get(0));
		} else {
			reader = PCSCUtils.TerminalForReaderName(readers.get(idx));
		}
		if (reader == null) {
			throw new ConformanceTestException("Unable to connect to card reader");
		}
		css.setTerminal(reader);

	}

	// this method will set up the card and piv application handles in the singleton
	// according to the reader index if specified
	public static boolean setUpPivAppHandleInSingleton() throws ConformanceTestException {
		CardSettingsSingleton css = CardSettingsSingleton.getInstance();
		CardTerminal reader = css.getTerminal();
		if (reader == null) {
			setUpReaderInSingleton();
			reader = css.getTerminal();
		}
		try {
			if (reader == null || !reader.isCardPresent()) {
				throw new ConformanceTestException("No card is present");
			}
		} catch (CardException e) {
			throw new ConformanceTestException("Failed to detect card presence", e);
		}
		CardHandle ch = css.getCardHandle();
		if (ch == null) {
			ConnectionDescription cd = ConnectionDescription.createFromTerminal(reader);
			ch = new CardHandle();
			MiddlewareStatus connectResult = PIVMiddleware.pivConnect(false, cd, ch);
			if (connectResult != MiddlewareStatus.PIV_OK) {
				throw new ConformanceTestException("pivConnect() failed: " + connectResult);
			}
			css.setCardHandle(ch);
			css.setPivHandle(null);
			DefaultPIVApplication piv = new CachingDefaultPIVApplication();
			ApplicationProperties cardAppProperties = new ApplicationProperties();
			ApplicationAID aid = new ApplicationAID();
			connectResult = piv.pivSelectCardApplication(ch, aid, cardAppProperties);
			if (connectResult != MiddlewareStatus.PIV_OK) {
				throw new ConformanceTestException("pivSelectCardApplication() failed");
			}
			css.setPivHandle(piv);
		}
		return true;
	}

	// this method will authenticate to the card
	public static boolean authenticateInSingleton(boolean useGlobal) throws ConformanceTestException {

		CardSettingsSingleton css = CardSettingsSingleton.getInstance();

		PIVAuthenticators authenticators = new PIVAuthenticators();

		if (css.getLastLoginStatus() != LOGIN_STATUS.LOGIN_SUCCESS) {

			if (useGlobal) {

				if (css.getGlobalPin() == null || css.getGlobalPin().length() == 0) {
					css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
					throw new ConformanceTestException("authenticateInSingleton() failed, missing global pin");
				}

				authenticators.addApplicationPin(css.getGlobalPin());
			} else {
				// Here, check whether this is invoked out of a Junit test in which case
				// there's no GUI, so give the user an opportunity to enter a pin.
				
				if (calledByJunit()) {
					s_logger.debug("authenticateSingleton() called by JUnit");
					Scanner scanInput = new Scanner(System.in);
					boolean done = false;
					while (!done) {
						String pIN;
						s_logger.debug("Please enter a PIN and press <RETURN>: ");
						pIN = scanInput.nextLine();
						s_logger.debug("Confirm PIN {} is correct (y/n): ", pIN);
						String conf = scanInput.nextLine();
						if (conf.contains("y") || conf.contains("Y")) {
							css.setApplicationPin(pIN);
							s_logger.debug("Setting PIN to {} and continuing...", pIN);
							done = true;
						}
					}
					scanInput.close();
                } else {
					s_logger.debug("authenticateSingleton() not called by JUnit");
				}
				if (css.getApplicationPin() == null || css.getApplicationPin().length() == 0) {
					css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
					throw new ConformanceTestException("authenticateInSingleton() failed, missing application pin");
				}

				authenticators.addApplicationPin(css.getApplicationPin());
			}

			// Get card handle and PIV handle
			CardHandle ch = css.getCardHandle();
			AbstractPIVApplication piv = css.getPivHandle();

			MiddlewareStatus result = piv.pivLogIntoCardApplication(ch, authenticators.getBytes());
			if (MiddlewareStatus.PIV_OK != result) {
				css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
				throw new ConformanceTestException("authenticateInSingleton() failed");
			}
		}

		// Cache the last login status status here, not inside the if block, guarantees
		// worst case is that a security requirement is not met.

		css.setLastLoginStatus(LOGIN_STATUS.LOGIN_SUCCESS);

		return true;
	}

	// this method will re-authenticate to the card
	public static boolean reauthenticateInSingleton() throws ConformanceTestException {

		CardSettingsSingleton css = CardSettingsSingleton.getInstance();

		PIVAuthenticators authenticators = new PIVAuthenticators();

		if (css.getLastLoginStatus() == LOGIN_STATUS.LOGIN_SUCCESS) {

			if (css.getApplicationPin() == null || css.getApplicationPin().length() == 0) {
				css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
				throw new ConformanceTestException("authenticateInSingleton() failed, missing application pin");
			}

			authenticators.addApplicationPin(css.getApplicationPin());

			// Get card handle and PIV handle
			CardHandle ch = css.getCardHandle();
			AbstractPIVApplication piv = css.getPivHandle();

			MiddlewareStatus result = piv.pivLogIntoCardApplication(ch, authenticators.getBytes());
			if (MiddlewareStatus.PIV_OK != result) {
				css.setLastLoginStatus(LOGIN_STATUS.LOGIN_FAIL);
				throw new ConformanceTestException("authenticateInSingleton() failed");
			}
		}

		// Cache the last login status status here, not inside the if block, guarantees
		// worst case is that a security requirement is not met.

		css.setLastLoginStatus(LOGIN_STATUS.LOGIN_SUCCESS);

		return true;
	}
	
	/**
	 * Indicates whether the calling method was invoked out of Junit
	 * Bottom of the stack when run from Eclipse Junit plugin is "org.eclipse.jdt.internal.junit.runner.RemoteTestRunner".
	 * Bottom of the Eclipse debugger stack is "java.awt.EventDispatchThread"
	 * Bottom of the distribution jar file stack is "java.awt.EventDispatchThread"
	 */

	public static boolean calledByJunit() {
		boolean rv = true;
		StackTraceElement[] stElements = Thread.currentThread().getStackTrace();
		String clazzStr = null;
		for (StackTraceElement st: stElements) {
			clazzStr = st.getClassName();
		}
		s_logger.debug("Last getClassName() returned " + clazzStr);
		rv = clazzStr.startsWith("org.eclipse.jdt.internal.junit");
		return rv;
	}
}
