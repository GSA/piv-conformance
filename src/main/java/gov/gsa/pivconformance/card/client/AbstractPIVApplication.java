package gov.gsa.pivconformance.card.client;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
/**
 * A base class for items that will implement the IPIVApplication interface, to allow those methods that can be
 * common across implementations to be shared
 */
abstract public class AbstractPIVApplication implements IPIVApplication {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(AbstractPIVApplication.class);

    @Override
    public MiddlewareStatus pivSelectCardApplication(CardHandle cardHandle, ApplicationAID applicationAID, ApplicationProperties applicationProperties) {

        try {
            // Establishing channel
            Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;

            // Establishing channel
            CardChannel channel = card.getBasicChannel();

            // Select applet, I looks like aways be the same not sure what ApplicationAID will be used for.
            CommandAPDU cmd = new CommandAPDU(APDUUtils.PIVSelectAPDU());
            //CommandAPDU cmd = new CommandAPDU(applicationAID.getBytes());

            // Transmit command and get response
            ResponseAPDU response = channel.transmit(cmd);

            // Populated thr response in ApplicationProperties
            applicationProperties.setBytes(response.getBytes());

        }
        catch (Exception ex) {

            s_logger.info("Error selecting card application: {}", ex.getMessage());
            return MiddlewareStatus.PIV_CONNECTION_FAILURE;
        }

        return MiddlewareStatus.PIV_OK;
    }

    @Override
    public MiddlewareStatus pivLogIntoCardApplication(CardHandle cardHandle, byte[] authenticators) {
        return null;
    }

    @Override
    public MiddlewareStatus pivGetData(CardHandle cardHandle, String OID, PIVDataObject data) {
        return null;
    }

    @Override
    public MiddlewareStatus pivLogoutOfCardApplication(CardHandle cardHandle) {
        return null;
    }

    @Override
    public MiddlewareStatus pivCrypt(CardHandle cardHandle, byte algorithmIdentifier, byte keyReference, PIVDataObject algorithmInput, PIVDataObject algorithmOutput) {
        return null;
    }
}
