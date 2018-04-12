package gov.gsa.pivconformance.card.client;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A default implementation of the PIV application interface that will be used by the test harness in most cases.
 */
public class DefaultPIVApplication extends AbstractPIVApplication {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(DefaultPIVApplication.class);

//    @Override
//    public MiddlewareStatus pivEstablishSecureMessaging(CardHandle cardHandle) {
//        return null;
//    }

    @Override
    public MiddlewareStatus pivPutData(CardHandle cardHandle, String OID, PIVDataObject data) {
        return null;
    }

    @Override
    public MiddlewareStatus pivSelectCardApplication(CardHandle cardHandle, ApplicationAID applicationAID, ApplicationProperties applicationProperties) {
        s_logger.debug("pivSelectCardApplication()");
        // For now, if the caller did not specify an AID, use the default.
        byte[] aid = applicationAID.getBytes();
        if(aid == null) {
            s_logger.info("Using default AID ({}) to select PIV application", Hex.encodeHexString(APDUConstants.PIV_APPID));
            applicationAID.setBytes(APDUConstants.PIV_APPID);
        }
        MiddlewareStatus rv = super.pivSelectCardApplication(cardHandle, applicationAID, applicationProperties);
        s_logger.debug("pivSelectCardApplication() returning {}", rv);
        return rv;
    }

//    @Override
//    public MiddlewareStatus pivGenerateKeyPair(CardHandle cardHandle, byte keyReference, byte cryptographicMechanism, PIVDataObject publicKey) {
//        return null;
//    }
}
