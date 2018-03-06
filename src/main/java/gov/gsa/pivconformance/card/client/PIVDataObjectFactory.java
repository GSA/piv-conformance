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
        PIVDataObject rv = null;

        if(OID.equals(APDUConstants.CARD_CAPABILITY_CONTAINER_OID))
            rv = new CardCapabilityContainer();
        else if(OID.equals(APDUConstants.CARD_HOLDER_UNIQUE_IDENTIFIER_OID))
            rv = new CardHolderUniqueIdentifier();
        else if(OID.equals(APDUConstants.SECURITY_OBJECT_OID))
            rv = new SecurityObject();
        else if(OID.equals(APDUConstants.CARDHOLDER_FACIAL_IMAGE_OID))
            rv = new CardholderBiometricData();
        else if(OID.equals(APDUConstants.CARDHOLDER_FINGERPRINTS_OID))
            rv = new CardholderBiometricData();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID))
            rv = new X509CertificateDataObject();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID))
            rv = new X509CertificateDataObject();
        else if(OID.equals(APDUConstants.DISCOVERY_OBJECT_OID))
            rv = new DiscoveryObject();
        else if(OID.equals(APDUConstants.KEY_HISTORY_OBJECT_OID))
            rv = new KeyHistoryObject();
        else if(OID.equals(APDUConstants.BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID))
            rv = new BiometricInformationTemplatesGroupTemplate();
        else if(OID.equals(APDUConstants.CARDHOLDER_IRIS_IMAGES_OID))
            rv = new CardholderBiometricData();
        else if(OID.equals(APDUConstants.PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID))
            rv = new PairingCodeReferenceDataContainer();
        else if(OID.equals(APDUConstants.SECURE_MESSAGING_CERTIFICATE_SIGNER_OID))
            rv = new SecureMessagingCertificateSigner();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID))
            rv = new X509CertificateDataObject();
        else if(OID.equals(APDUConstants.X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID))
            rv = new X509CertificateDataObject();
        else if(OID.equals(APDUConstants.PRINTED_INFORMATION_OID))
            rv = new PrintedInformation();

        if(rv == null) {
            s_logger.warn("Unrecognized data object type. Using generic.");
            rv = new PIVDataObject();
        }
        rv.setOID(OID);
        return rv;
    }
}
