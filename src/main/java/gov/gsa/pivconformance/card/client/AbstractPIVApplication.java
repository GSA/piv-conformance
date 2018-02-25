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

            //Construct APDU command using APDUUtils and applicationAID that was passed in.
            CommandAPDU cmd = new CommandAPDU(APDUUtils.PIVSelectAPDU(applicationAID.getBytes()));

            // Transmit command and get response
            ResponseAPDU response = channel.transmit(cmd);

            //Check for Successful execution status word
            if(response.getSW() != APDUConstants.SUCCESSFUL_EXEC) {

                if(response.getSW() != APDUConstants.APP_NOT_FOUND){
                    s_logger.info("Card application not found");
                    return MiddlewareStatus.PIV_CARD_APPLICATION_NOT_FOUND;
                }

                s_logger.error("Error selecting card application, failed with error: {}", Integer.toHexString(response.getSW()));
                return MiddlewareStatus.PIV_CONNECTION_FAILURE;
            }

            // Populated the response in ApplicationProperties
            applicationProperties.setBytes(response.getData());

        }
        catch (Exception ex) {

            s_logger.error("Error selecting card application: {}", ex.getMessage());
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

        try {
            // Establishing channel
            Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;

            // Establishing channel
            CardChannel channel = card.getBasicChannel();

        }catch (SecurityException ex) {

            s_logger.info("Error retrieving data from the card application: {}", ex.getMessage());
            return MiddlewareStatus.PIV_SECURITY_CONDITIONS_NOT_SATISFIED;
        }
        catch (Exception ex) {

            s_logger.info("Error retrieving data from the card application: {}", ex.getMessage());
            return MiddlewareStatus.PIV_CONNECTION_FAILURE;
        }

        return MiddlewareStatus.PIV_OK;
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
