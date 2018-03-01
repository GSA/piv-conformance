package gov.gsa.pivconformance.card.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PIVDataObjectFactory {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVDataObjectFactory.class);

    /**
     * Instantiate an appropriate PIVDataObject class given an OID, or a generic one in the absence of an OID
     *
     * @param OID
     * @return
     */
    public static PIVDataObject createDataObjectForOid(String OID) {

        if(OID.equals(APDUConstants.CARD_CAPABILITY_CONTAINER_OID))
            return new CardCapabilityContainer();
        else if(OID.equals(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID))
            return new CardHolderUniqueIdentifier();
        else if(OID.equals(APDUConstants.SECURITY_OBJECT_OID))
            return new SecurityObject();
        else if(OID.equals(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID))
            return new CardholderFacialImage();
        else if(OID.equals(APDUConstants.CARDHOLDER_FINGERPRINTS_OID))
            return new CardholderFingerprints();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID))
            return new X509CertificateForCardAuthentication();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID))
            return new X509CertificateForPIVAuthentication();
        else if(OID.equals(APDUConstants.DISCOVERY_OBJECT_OID))
            return new PIVDataObject();
        else if(OID.equals(APDUConstants.KEY_HISTORY_OBJECT_OID))
            return new KeyHistoryObject();
        else if(OID.equals(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID))
            return new BiometricInformationTemplatesGroupTemplate();
        else if(OID.equals(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID))
            return new CardholderIrisImages();
        else if(OID.equals(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID))
            return new PairingCodeReferenceDataContainer();
        else if(OID.equals(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID))
            return new SecureMessagingCertificateSigner();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID))
            return new X509CertificateForDigitalSignature();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID))
            return new X509CertificateForKeyManagment();
        else if(OID.equals(APDUConstants.PRINTED_INFORMATION_OID))
            return new PrintedInformation();

        return new PIVDataObject();
    }
}
