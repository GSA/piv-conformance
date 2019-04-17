package gov.gsa.pivconformance.card.client;

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
    private CommandAPDU m_lastCommandAPDU = null;
    private ResponseAPDU m_lastResponseAPDU;

    /**
     *
     * Set the PIV Card Application as the currently selected card application and establish
     * the PIV Card Applicationâs security state.
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param applicationAID ApplicationAID object containing the AID of the PIV Card Application
     * @param applicationProperties ApplicationProperties object containing application properties of the selected PIV
     * Card Application
     * @return MiddlewareStatus value indicating the result of the function call
     */
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
            m_lastCommandAPDU = cmd; m_lastResponseAPDU = null;
            // Transmit command and get response
            ResponseAPDU response = channel.transmit(cmd);
            m_lastResponseAPDU = response;
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

    /**
     *
     * Sets security state within the PIV Card Application.
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param authenticators Byte array cotaining authenticators to be used to authenticate and set security
     * state/status in the PIV Card Application context
     * @return MiddlewareStatus value indicating the result of the function call
     */
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
            //s_logger.debug("VERIFY APDU: {}", Hex.encodeHexString(rawAPDU));
            CardChannel channel = cardHandle.getCurrentChannel();
            CommandAPDU verifyApdu = new CommandAPDU(rawAPDU);
            ResponseAPDU resp = null;
            try {
                m_lastCommandAPDU = verifyApdu; m_lastResponseAPDU = null;
                resp = channel.transmit(verifyApdu);
                m_lastResponseAPDU = resp;
            } catch (CardException e) {
                s_logger.error("Failed to transmit VERIFY APDU to card", e);
                return MiddlewareStatus.PIV_CARD_READER_ERROR;
            }
            if(resp.getSW() == 0x9000) {
                cardHandle.setCurrentChannel(channel);
                s_logger.debug("Successfully logged into card application");
            } else {
                s_logger.error("Login failed: {}", Hex.encodeHexString(resp.getBytes()));
                return MiddlewareStatus.PIV_AUTHENTICATION_FAILURE;
            }

        }
        return MiddlewareStatus.PIV_OK;
    }

    /**
     *
     * Retrieves all the data containers of the PIV Card Application
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param dataList List of PIVDataObject objects containing all the data containers of PIV Card Application
     * @return MiddlewareStatus value indicating the result of the function call
     */
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

    /**
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param OID String containing OID value identifying data object whose data content is to be
     * retrieved
     * @param data PIVDataObject object that will store retrieved data content
     * @return MiddlewareStatus value indicating the result of the function call
     */
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
            baos.write(TagConstants.DATA_FIELD_TAG);
            baos.write(APDUConstants.oidMAP.get(OID).length);
            baos.write(APDUConstants.oidMAP.get(OID));

            //Construct APDU command using APDUUtils and applicationAID that was passed in.
            CommandAPDU cmd = new CommandAPDU(APDUUtils.PIVGetDataAPDU(baos.toByteArray()));

            // Transmit command and get response
            m_lastCommandAPDU = cmd; m_lastResponseAPDU = null;
            ResponseAPDU response = channel.transmit(cmd);
            m_lastResponseAPDU = response;

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

    /**
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param OID String containing OID value identifying data object whose data content is to be
     * retrieved
     * @param data PIVDataObject object that will store retrieved data content
     * @return MiddlewareStatus value indicating the result of the function call
     */
    public MiddlewareStatus pivGetAllData(CardHandle cardHandle, String OID, PIVDataObject data) {

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
            baos.write(TagConstants.DATA_FIELD_TAG);
            baos.write(0x00);
            baos.write(APDUConstants.oidMAP.get(OID));

            //Construct APDU command using APDUUtils and applicationAID that was passed in.
            CommandAPDU cmd = new CommandAPDU(APDUUtils.PIVGetDataAPDU(baos.toByteArray()));

            // Transmit command and get response
            m_lastCommandAPDU = cmd; m_lastResponseAPDU = null;
            ResponseAPDU response = channel.transmit(cmd);
            m_lastResponseAPDU = response;

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

    /**
     *
     * Reses the application security state/status of the PIV Card Application.
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @return MiddlewareStatus value indicating the result of the function call
     */
    @Override
    public MiddlewareStatus pivLogoutOfCardApplication(CardHandle cardHandle) {
        return null;
    }

    /**
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param algorithmIdentifier Byte value identifying the cryptographic algorithm to be used for
     * the cryptographic operation
     * @param keyReference Byte value identifying the on-card key to be used for the
     * cryptographic operation.
     * @param algorithmInput PIVDataObject object containing sequence of bytes used as the input to the cryptographic
     * operation
     * @param algorithmOutput PIVDataObject object containing sequence of bytes used as the output to the cryptographic
     *      * operation
     * @return MiddlewareStatus value indicating the result of the function call
     */
    @Override
    public MiddlewareStatus pivCrypt(CardHandle cardHandle, byte algorithmIdentifier, byte keyReference,
    		PIVDataObject algorithmInput, PIVDataObject algorithmOutput) {
    	try {
    		Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;
            
            CardChannel channel = card.getBasicChannel();
            if(channel == null)
            	return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;
            
            byte[] rawAPDU = APDUUtils.PIVGeneralAuthenticateAPDU(keyReference, algorithmIdentifier, algorithmInput.getBytes());
            s_logger.info("GENERAL AUTHENTICATE APDU: {}", Hex.encodeHexString(rawAPDU));
            
            
            CommandAPDU cmd = new CommandAPDU(rawAPDU);
            // Transmit command and get response
            m_lastCommandAPDU = cmd; m_lastResponseAPDU = null;
            ResponseAPDU response = channel.transmit(cmd);
            m_lastResponseAPDU = response;
            
            s_logger.debug("Response to GENERAL AUTHENTICATE command: {} {}", String.format("0x%02X", response.getSW1()), String.format("0x%02X", response.getSW2()));

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
                    s_logger.error("Error in GENERAL AUTHENTICATE command, failed with error: {}", Integer.toHexString(response.getSW()));
                    return MiddlewareStatus.PIV_CONNECTION_FAILURE;
                }
            }
    		algorithmOutput.setBytes(response.getData());
    		cardHandle.setCurrentChannel(channel);
    	} catch(Exception e) {
    		s_logger.error("Failed to complete pivCrypt operation for algorithm {} (key {}",
    				Hex.encodeHexString(new byte[] {algorithmIdentifier}), Hex.encodeHexString(new byte[] {keyReference}), e);
    	}
        return null;
    }

    /**
     *
     *  Generates an asymmetric key pair in the currently selected card application.
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param keyReference Byte value identifying key reference of the generated key pair
     * @param cryptographicMechanism Byte value identifying the type of key pair to be generated
     * @param publicKey PIVDataObject object defining the public key of the generated key pair
     * @return MiddlewareStatus value indicating the result of the function call
     */
    public MiddlewareStatus pivGenerateKeyPair(CardHandle cardHandle, byte keyReference, byte cryptographicMechanism, PIVDataObject publicKey){
        try {
            // Establishing channel
            Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;

            // Establishing channel
            CardChannel channel = card.getBasicChannel();

            //Construct APDU command using APDUUtils and keyReference, cryptographicMechanism that was passed in.
            byte[] rawAPDU = APDUUtils.PIVGenerateKeyPairAPDU(keyReference, cryptographicMechanism, null);
            s_logger.info("GENERATE APDU: {}", Hex.encodeHexString(rawAPDU));

            CommandAPDU cmd = new CommandAPDU(rawAPDU);

            // Transmit command and get response
            m_lastCommandAPDU = cmd; m_lastResponseAPDU = null;
            ResponseAPDU response = channel.transmit(cmd);
            m_lastResponseAPDU = response;
            
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

    /**
     * Establishes secure messaging with the PIV Card Application.
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @return MiddlewareStatus value indicating the result of the function call
     */
    @Override
    public MiddlewareStatus pivEstablishSecureMessaging(CardHandle cardHandle) {
        s_logger.debug("pivEstablishSecureMessaging()");
        try {
            // Establishing channel
            Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;


            byte[] dataField = { (byte) 0x7C, 0x05, (byte) 0x81, 0x01, 0x00, (byte) 0x82, 0x00 };

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.SM);
                baos.write(APDUConstants.CIPHER_SUITE_1); // Algorithm Reference for algs that support SM.
                baos.write(APDUConstants.PIV_SECURE_MESSAGING_KEY);
                baos.write(dataField.length);
                baos.write(dataField);
                baos.write(0x00); //Le
            } catch(IOException ioe) {
                s_logger.error("Failed to populate SM APDU buffer");
            }
            byte[] rawAPDU = baos.toByteArray();
            s_logger.info("SM APDU: {}", Hex.encodeHexString(rawAPDU));
            CardChannel channel = cardHandle.getCurrentChannel();
            CommandAPDU smApdu = new CommandAPDU(rawAPDU);
            ResponseAPDU resp = null;
            try {
            	m_lastCommandAPDU = smApdu; m_lastResponseAPDU = null;
                resp = channel.transmit(smApdu);
                m_lastResponseAPDU = resp;
            } catch (CardException e) {
                s_logger.error("Failed to transmit SM APDU to card", e);
                return MiddlewareStatus.PIV_CARD_READER_ERROR;
            }
            if(resp.getSW() == 0x9000) {
                cardHandle.setCurrentChannel(channel);
                s_logger.info("Successfully established secure messaging");
            } else {
                s_logger.error("Error establishing secure messaging: {}", Hex.encodeHexString(resp.getBytes()));
                return MiddlewareStatus.PIV_SM_FAILED;
            }

        }
        catch (Exception ex) {

            s_logger.error("Error establishing secure messaging: {}", ex.getMessage());
            return MiddlewareStatus.PIV_CARD_READER_ERROR;
        }
        s_logger.debug("pivSelectCardApplication returning {}", MiddlewareStatus.PIV_OK);
        return MiddlewareStatus.PIV_OK;
    }

    /**
     *  Replaces the entire data content of the data object specified by the OID parameter with the provided data.
     *
     * @param cardHandle CardHandle object that encapsulates connection to a card
     * @param OID String containing OID value identifying data object
     * @param data PIVDataObject object containing data that will be written to the card
     * @return MiddlewareStatus value indicating the result of the function call
     */
    @Override
    public MiddlewareStatus pivPutData(CardHandle cardHandle, String OID, PIVDataObject data) {

        s_logger.debug("pivPutData()");
        try {
            // Establishing channel
            Card card = cardHandle.getCard();
            if (card == null)
                return MiddlewareStatus.PIV_INVALID_CARD_HANDLE;

            if (OID == null)
                return MiddlewareStatus.PIV_INVALID_OID;



            ByteArrayOutputStream baosDataField = new ByteArrayOutputStream();
            if(data.getOID().equals(APDUConstants.DISCOVERY_OBJECT_OID) || data.getOID().equals(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID)){

                baosDataField.write(data.getBytes());
            }
            else {
                baosDataField.write(TagConstants.TAG_LIST);
                baosDataField.write(APDUConstants.oidMAP.get(OID).length);
                baosDataField.write(APDUConstants.oidMAP.get(OID));
                baosDataField.write(data.getBytes());
            }

            s_logger.debug("dataField: {}", Hex.encodeHexString(baosDataField.toByteArray()));

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try {
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.INS_DB);
                baos.write(APDUConstants.P1_3F);
                baos.write(APDUConstants.P2_FF);
                baos.write(baosDataField.toByteArray().length);
                baos.write(baosDataField.toByteArray());
            } catch(IOException ioe) {
                s_logger.error("Failed to populate PUT DATA APDU buffer");
            }
            byte[] rawAPDU = baos.toByteArray();
            s_logger.info("PUT DATA APDU: {}", Hex.encodeHexString(rawAPDU));
            CardChannel channel = cardHandle.getCurrentChannel();
            CommandAPDU smApdu = new CommandAPDU(rawAPDU);
            ResponseAPDU resp = null;
            try {
            	m_lastCommandAPDU = smApdu; m_lastResponseAPDU = null;
                resp = channel.transmit(smApdu);
                m_lastResponseAPDU = resp;
            } catch (CardException e) {
                s_logger.error("Failed to transmit PUT DATA APDU to card", e);
                return MiddlewareStatus.PIV_CARD_READER_ERROR;
            }
            if(resp.getSW() == 0x9000) {
                cardHandle.setCurrentChannel(channel);
                s_logger.info("Successfully wrote data object to the card.");
            } else if(resp.getSW() == 0x6A82){
                s_logger.error("Failed to write object to the card, security condition not satisfied: {}", Hex.encodeHexString(resp.getBytes()));
                return MiddlewareStatus.PIV_SECURITY_CONDITIONS_NOT_SATISFIED;
            } else if(resp.getSW() == 0x6A81){
                s_logger.error("Failed to write object to the card, function is not supported: {}", Hex.encodeHexString(resp.getBytes()));
                return MiddlewareStatus.PIV_FUNCTION_NOT_SUPPORTED;
            } else if(resp.getSW() == 0x6A84){
                s_logger.error("Failed to write object to the card, not enough memory: {}", Hex.encodeHexString(resp.getBytes()));
                return MiddlewareStatus.PIV_INSUFFICIENT_CARD_RESOURCE;
            } else {
                s_logger.error("Failed to write object to the card: {}", Hex.encodeHexString(resp.getBytes()));
                return MiddlewareStatus.PIV_CARD_READER_ERROR;
            }

        }
        catch (Exception ex) {

            s_logger.error("Error writing data object to the card: {}", ex.getMessage());
            return MiddlewareStatus.PIV_CARD_READER_ERROR;
        }
        s_logger.debug("pivPutData returning {}", MiddlewareStatus.PIV_OK);
        return MiddlewareStatus.PIV_OK;
    }
    
    public byte[] getLastCommandAPDUBytes()
    {
    	byte[] apduBytes = null;
    	if(m_lastCommandAPDU == null) {
    		s_logger.error("getLastCommandAPDUBytes() called without any command APDU having been sent.");
    		return apduBytes;
    	}
    	apduBytes = m_lastCommandAPDU.getBytes();
    	return apduBytes;
    }
    
    public byte[] getLastResponseAPDUBytes()
    {
    	byte[] apduBytes = null;
    	if(m_lastResponseAPDU == null) {
    		s_logger.error("getLastResponseAPDUBytes() called without any command APDU having been sent.");
    		return apduBytes;
    	}
    	apduBytes = m_lastResponseAPDU.getBytes();
    	return apduBytes;
    }
}
