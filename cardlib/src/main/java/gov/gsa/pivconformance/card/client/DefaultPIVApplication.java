package gov.gsa.pivconformance.card.client;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A default implementation of the PIV application interface that will be used
 * by the test harness in most cases.
 */
public class DefaultPIVApplication extends AbstractPIVApplication {
	// slf4j will thunk this through to an appropriately configured logging library
	private static final Logger s_logger = LoggerFactory.getLogger(DefaultPIVApplication.class);

	/**
	 *
	 * Set the PIV Card Application as the currently selected card application and
	 * establish the PIV Card Applicationâs security state.
	 *
	 * @param cardHandle            CardHandle object that encapsulates connection
	 *                              to a card
	 * @param applicationAID        ApplicationAID object containing the AID of the
	 *                              PIV Card Application
	 * @param applicationProperties ApplicationProperties object containing
	 *                              application properties of the selected PIV Card
	 *                              Application
	 * @return
	 */
	@Override
	public MiddlewareStatus pivSelectCardApplication(CardHandle cardHandle, ApplicationAID applicationAID,
			ApplicationProperties applicationProperties) {
		s_logger.debug("pivSelectCardApplication()");
		// For now, if the caller did not specify an AID, use the default.
		byte[] aid = applicationAID.getBytes();
		if (aid == null) {
			s_logger.info("Using default AID ({}) to select PIV application",
					Hex.encodeHexString(APDUConstants.PIV_APPID));
			applicationAID.setBytes(APDUConstants.PIV_APPID);
		}
		MiddlewareStatus rv = super.pivSelectCardApplication(cardHandle, applicationAID, applicationProperties);
		s_logger.debug("pivSelectCardApplication() returning {}", rv);
		return rv;
	}
}
