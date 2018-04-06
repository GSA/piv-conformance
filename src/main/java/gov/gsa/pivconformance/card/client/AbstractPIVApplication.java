package gov.gsa.pivconformance.card.client;


import gov.gsa.pivconformance.tlv.BerTlvParser;
import gov.gsa.pivconformance.tlv.BerTlvs;
import gov.gsa.pivconformance.tlv.CCTTlvLogger;
import gov.gsa.pivconformance.tlv.TagConstants;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

/**
 * A base class for items that will implement the IPIVApplication interface, to allow those methods that can be
 * common across implementations to be shared
 */
abstract public class AbstractPIVApplication implements IPIVApplication {

    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(AbstractPIVApplication.class);

    @Override
    public MiddlewareStatus pivSelectCardApplication(CardHandle cardHandle, ApplicationAID applicationAID, ApplicationProperties applicationProperties) {
        s_logger.debug("pivSelectCardApplication()");
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
            s_logger.debug("Response to SELECT command: {} {}", String.format("0x%02X", response.getSW1()), String.format("0x%02X", response.getSW2()));

            //Check for Successful execution status word
            if(response.getSW() != APDUConstants.SUCCESSFUL_EXEC) {

                if(response.getSW() == APDUConstants.APP_NOT_FOUND){
                    s_logger.info("Card application not found");
                    return MiddlewareStatus.PIV_CARD_APPLICATION_NOT_FOUND;
                }

                s_logger.error("Error selecting card application, failed with error: {}", Integer.toHexString(response.getSW()));
                return MiddlewareStatus.PIV_CONNECTION_FAILURE;
            }

            // Populated the response in ApplicationProperties
            applicationProperties.setBytes(response.getData());
            cardHandle.setCurrentChannel(channel);

        }
        catch (Exception ex) {

            s_logger.error("Error selecting card application: {}", ex.getMessage());
            return MiddlewareStatus.PIV_CONNECTION_FAILURE;
        }
        s_logger.debug("pivSelectCardApplication returning {}", MiddlewareStatus.PIV_OK);
        return MiddlewareStatus.PIV_OK;
    }

    @Override
    public MiddlewareStatus pivLogIntoCardApplication(CardHandle cardHandle, byte[] authenticators) {
        PIVAuthenticators pas = new PIVAuthenticators();
        pas.decode(authenticators);
        for(PIVAuthenticator authenticator : pas.getAuthenticators()) {
            if(authenticator.getType() != TagConstants.KEY_REFERENCE_APPLICATION_PIN_TAG &&
                    authenticator.getType() != TagConstants.KEY_REFERENCE_GLOBAL_PIN_TAG ) {
                s_logger.warn("Skipping authenticator of type {}. Currently unsupported.", authenticator.getType());
                continue;
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.VERIFY);
                baos.write((byte) 0x00); // logging in
                baos.write(authenticator.getType());
                baos.write((byte) 0x08); // PIN
                baos.write(authenticator.getData());
            } catch(IOException ioe) {
                s_logger.error("Failed to populate VERIFY APDU buffer");
            }
            byte[] rawAPDU = baos.toByteArray();
            s_logger.info("VERIFY APDU: {}", Hex.encodeHexString(rawAPDU));
            CardChannel channel = cardHandle.getCurrentChannel();
            CommandAPDU verifyApdu = new CommandAPDU(rawAPDU);
            ResponseAPDU resp = null;
            try {
                resp = channel.transmit(verifyApdu);
            } catch (CardException e) {
                s_logger.error("Failed to transmit VERIFY APDU to card", e);
                return MiddlewareStatus.PIV_CARD_READER_ERROR;
            }
            if(resp.getSW() == 0x9000) {
                cardHandle.setCurrentChannel(channel);
                s_logger.info("Successfully logged into card application");
            } else {
                s_logger.error("Login failed: {}", Hex.encodeHexString(resp.getBytes()));
                return MiddlewareStatus.PIV_AUTHENTICATION_FAILURE;
            }

        }
        return MiddlewareStatus.PIV_OK;
    }

    public MiddlewareStatus pivGetAllDataContainers(CardHandle cardHandle, List<PIVDataObject> dataList) {

        MiddlewareStatus result = MiddlewareStatus.PIV_OK;

        if (cardHandle == null)
            return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;

        try {
            if(dataList == null)
                dataList = new ArrayList<PIVDataObject>();

            for(String containerOID : APDUConstants.AllContainers()){

                //Create object from the OID
                PIVDataObject dataObject = PIVDataObjectFactory.createDataObjectForOid(containerOID);
                s_logger.info("Attempting to read data object for OID {} ({})", containerOID, APDUConstants.oidNameMAP.get(containerOID));

                result = this.pivGetData(cardHandle, containerOID, dataObject);

                //Add the data object to the list if successful return code
                if(result == MiddlewareStatus.PIV_OK)
                    dataList.add(dataObject);
            }


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
    public MiddlewareStatus pivGetData(CardHandle cardHandle, String OID, PIVDataObject data) {

        try {
            // Establishing channel
            Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;

            CardChannel channel = cardHandle.getCurrentChannel();
            if(channel == null) {
                throw new IllegalStateException("Must select PIV application before calling pivGetData");
            }

            //Construct data field based on the data field oid and the tag for the specific oid
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(APDUConstants.DATA_FIELD_TAG);
            baos.write(APDUConstants.oidMAP.get(OID).length);
            baos.write(APDUConstants.oidMAP.get(OID));

            //Construct APDU command using APDUUtils and applicationAID that was passed in.
            CommandAPDU cmd = new CommandAPDU(APDUUtils.PIVGetDataAPDU(baos.toByteArray()));

            // Transmit command and get response
            ResponseAPDU response = channel.transmit(cmd);

            //Check for Successful execution status word
            if(response.getSW() != APDUConstants.SUCCESSFUL_EXEC) {

                if(response.getSW() == APDUConstants.APP_NOT_FOUND){
                    s_logger.info("Data object not found");
                    return MiddlewareStatus.PIV_DATA_OBJECT_NOT_FOUND;
                }
                else if(response.getSW() == APDUConstants.SECURITY_STATUS_NOT_SATISFIED){
                    s_logger.info("Security status not satisfied");
                    return MiddlewareStatus.PIV_SECURITY_CONDITIONS_NOT_SATISFIED;
                }

                s_logger.error("Error getting object {}, failed with error: {}", OID, Integer.toHexString(response.getSW()));
                return MiddlewareStatus.PIV_CONNECTION_FAILURE;
            }

            // Populate the response in PIVDataObject
            data.setOID(OID);
            data.setBytes(response.getData());

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

    public MiddlewareStatus pivGenerateKeyPair(CardHandle cardHandle, byte keyReference, byte cryptographicMechanism, PIVDataObject publicKey){
        try {
            // Establishing channel
            Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;

            // Establishing channel
            CardChannel channel = card.getBasicChannel();

            //Construct APDU command using APDUUtils and applicationAID that was passed in.
            CommandAPDU cmd = new CommandAPDU(APDUUtils.PIVGenerateKeyPairAPDU(keyReference, cryptographicMechanism, null));

            // Transmit command and get response
            ResponseAPDU response = channel.transmit(cmd);
            s_logger.debug("Response to GENERATE command: {} {}", String.format("0x%02X", response.getSW1()), String.format("0x%02X", response.getSW2()));

            //Check for Successful execution status word
            if(response.getSW() != APDUConstants.SUCCESSFUL_EXEC) {

                if(response.getSW() == APDUConstants.SECURITY_STATUS_NOT_SATISFIED){
                    s_logger.error("Security condition not satisfied");
                    return MiddlewareStatus.PIV_SECURITY_CONDITIONS_NOT_SATISFIED;
                }
                else if(response.getSW() == APDUConstants.INCORREECT_PARAMETER){
                    s_logger.error("Incorrect parameter in command data field");
                    return MiddlewareStatus.PIV_UNSUPPORTED_CRYPTOGRAPHIC_MECHANISM;
                }
                else if(response.getSW() == APDUConstants.FUNCTION_NOT_SUPPORTED){
                    s_logger.error("Function not supported");
                    return MiddlewareStatus.PIV_FUNCTION_NOT_SUPPORTED;
                }
                else if(response.getSW() == APDUConstants.INCORREECT_PARAMETER_P2){
                    s_logger.error("Invalid key or key algorithm combination");
                    return MiddlewareStatus.PIV_INVALID_KEY_OR_KEYALG_COMBINATION;
                }
                else {
                    s_logger.error("Error generating key pair, failed with error: {}", Integer.toHexString(response.getSW()));
                    return MiddlewareStatus.PIV_CONNECTION_FAILURE;
                }
            }

            // Populated the response in ApplicationProperties
            publicKey.setBytes(response.getData());
            cardHandle.setCurrentChannel(channel);

        }
        catch (Exception ex) {

            s_logger.error("Error generating key pair: {}", ex.getMessage());
            return MiddlewareStatus.PIV_CONNECTION_FAILURE;
        }
        s_logger.debug("pivGenerateKeyPair returning {}", MiddlewareStatus.PIV_OK);
        return MiddlewareStatus.PIV_OK;
    }
}
