package gov.gsa.pivconformance.card.client;


import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.lang.IllegalArgumentException;

public class APDUConstants {

    public static final String DEFAULTHASHALG = "SHA-256";
    public static final byte COMMAND = 0x00;
    public static final byte COMMAND_CC = 0x10;
    public static final byte SELECT = (byte)0xa4;
    public static final byte GENERATE = (byte)0x47;
    public static final byte GET = (byte)0xcb;
    public static final byte VERIFY = 0x20;
    public static final byte SM = (byte)0x87;
    public static final byte INS_DB = (byte)0xDB;
    public static final byte P1_3F = 0x3F;
    public static final byte P2_FF = (byte)0xFF;
    public static final byte[] PIV_APPID = { (byte)0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };

    public static final int SUCCESSFUL_EXEC = 0x9000;

    public static final int CIPHER_SUITE_1 = 0x27;
    public static final int CIPHER_SUITE_2 = 0x2E;


    public static final byte PIV_SECURE_MESSAGING_KEY = 0x04;
    public static final byte PIV_AUTHENTICATION_KEY = (byte) 0x9A;
    public static final byte PIV_CARD_APPLICATION_ADMINISTRATION_KEY = (byte) 0x9B;
    public static final byte DIGITAL_SIGNATURE_KEY = (byte) 0x9C;
    public static final byte KEY_MANAGEMENT_KEY = (byte) 0x9D;
    public static final byte KEY_AUTHENTICATION_KEY = (byte) 0x9D;
    public static final byte RETIRED_KEY_MANAGEMENT_KEY = (byte) 0x82;

    public static final byte CRYPTO_MECHANISM_RSA = 0x07;
    public static final byte CRYPTO_MECHANISM_ECC_P286 = 0x11;
    public static final byte CRYPTO_MECHANISM_ECC_P384 = 0x14;


    public static final byte CONTROL_REFERENCE_TEMPLATE_TAG = (byte) 0xAC;


    public static final int APP_NOT_FOUND = 0x6A82;
    public static final int SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    public static final int INCORREECT_PARAMETER = 0x6A80;
    public static final int FUNCTION_NOT_SUPPORTED = 0x6A81;
    public static final int INCORREECT_PARAMETER_P2 = 0x6A86;

    public static final String CARD_CAPABILITY_CONTAINER_OID = "2.16.840.1.101.3.7.1.219.0";
    public static final byte[] CARD_CAPABILITY_CONTAINER_TAG =  {0x5F, (byte)0xC1, 0x07};
    public static final int CARD_CAPABILITY_CONTAINER_ID =  0xDB00;
    public static final String CARD_CAPABILITY_CONTAINER_NAME = "Card Capability Container";

    public static final String CARD_HOLDER_UNIQUE_IDENTIFIER_OID = "2.16.840.1.101.3.7.2.48.0";
    public static final byte[] CARD_HOLDER_UNIQUE_IDENTIFIER_TAG = {0x5F, (byte)0xC1, 0x02};
    public static final int CARD_HOLDER_UNIQUE_IDENTIFIER_ID = 0x3000;
    public static final String CARD_HOLDER_UNIQUE_IDENTIFIER_NAME = "Card Holder Unique Identifier";

    public static final String X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID = "2.16.840.1.101.3.7.2.1.1";
    public static final byte[] X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_TAG = {0x5F, (byte)0xC1, 0x05};
    public static final int X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_ID = 0x0101;
    public static final String X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_NAME = "X.509 Certificate for PIV Authentication (Key Reference '9A')";

    public static final String CARDHOLDER_FINGERPRINTS_OID = "2.16.840.1.101.3.7.2.96.16";
    public static final byte[] CARDHOLDER_FINGERPRINTS_TAG = {0x5F, (byte)0xC1, 0x03};
    public static final int CARDHOLDER_FINGERPRINTS_ID = 0x6010;
    public static final String CARDHOLDER_FINGERPRINTS_NAME = "Cardholder Fingerprints";


    public static final String SECURITY_OBJECT_OID = "2.16.840.1.101.3.7.2.144.0";
    public static final byte[] SECURITY_OBJECT_TAG = {0x5F, (byte)0xC1, 0x06};
    public static final int SECURITY_OBJECT_ID = 0x9000;
    public static final String SECURITY_OBJECT_NAME = "Security Object";

    public static final String CARDHOLDER_FACIAL_IMAGE_OID = "2.16.840.1.101.3.7.2.96.48";
    public static final byte[] CARDHOLDER_FACIAL_IMAGE_TAG = {0x5F, (byte)0xC1, 0x08};
    public static final int CARDHOLDER_FACIAL_IMAGE_ID = 0x6030;
    public static final String CARDHOLDER_FACIAL_IMAGE_NAME = "Cardholder Facial Image";

    public static final String X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID = "2.16.840.1.101.3.7.2.5.0";
    public static final byte[] X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_TAG = {0x5F, (byte)0xC1, 0x01};
    public static final int X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_ID = 0x0500;
    public static final String X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_NAME = "X.509 Certificate for Card Authentication (Key Reference '9E')";

    public static final String X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID = "2.16.840.1.101.3.7.2.1.0";
    public static final byte[] X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_TAG = {0x5F, (byte)0xC1, 0x0A};
    public static final int X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_ID = 0x0100;
    public static final String X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_NAME = "X.509 Certificate for Digital Signature (Key Reference '9C')";


    public static final String X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID = "2.16.840.1.101.3.7.2.1.2";
    public static final byte[] X509_CERTIFICATE_FOR_KEY_MANAGEMENT_TAG = {0x5F, (byte)0xC1, 0x0B};
    public static final int X509_CERTIFICATE_FOR_KEY_MANAGEMENT_ID = 0x0102;
    public static final String X509_CERTIFICATE_FOR_KEY_MANAGEMENT_NAME = "X.509 Certificate for Key Management (Key Reference '9D')";


    public static final String PRINTED_INFORMATION_OID = "2.16.840.1.101.3.7.2.48.1";
    public static final byte[] PRINTED_INFORMATION_TAG = {0x5F, (byte)0xC1, 0x09};
    public static final int PRINTED_INFORMATION_ID = 0x3001;
    public static final String PRINTED_INFORMATION_NAME = "Printed Information";


    public static final String DISCOVERY_OBJECT_OID = "2.16.840.1.101.3.7.2.96.80";
    public static final byte[] DISCOVERY_OBJECT_TAG = {0x7E};
    public static final int DISCOVERY_OBJECT_ID = 0x6050;
    public static final String DISCOVERY_OBJECT_NAME = "Discovery Object";


    public static final String KEY_HISTORY_OBJECT_OID = "2.16.840.1.101.3.7.2.96.96";
    public static final byte[] KEY_HISTORY_OBJECT_TAG = {0x5F, (byte)0xC1, 0x0C};
    public static final int KEY_HISTORY_OBJECT_ID = 0x6060;
    public static final String KEY_HISTORY_OBJECT_NAME = "Key History Object";


    public static final String CARDHOLDER_IRIS_IMAGES_OID = "2.16.840.1.101.3.7.2.16.21";
    public static final byte[] CARDHOLDER_IRIS_IMAGES_TAG = {0x5F, (byte)0xC1, 0x21};
    public static final int CARDHOLDER_IRIS_IMAGES_ID = 0x1015;
    public static final String CARDHOLDER_IRIS_IMAGES_NAME = "Cardholder Iris Images";


    public static final String BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID = "2.16.840.1.101.3.7.2.16.22";
    public static final byte[] BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_TAG = {0x7F, 0x61};
    public static final int BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_ID = 0x1016;
    public static final String BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_NAME = "Biometric Information Templates Group Template";


    public static final String SECURE_MESSAGING_CERTIFICATE_SIGNER_OID = "2.16.840.1.101.3.7.2.16.23";
    public static final byte[] SECURE_MESSAGING_CERTIFICATE_SIGNER_TAG = {0x5F, (byte)0xC1, 0x22};
    public static final int SECURE_MESSAGING_CERTIFICATE_SIGNER_ID = 0x1017;
    public static final String SECURE_MESSAGING_CERTIFICATE_SIGNER_NAME = "Secure Messaging Certificate Signer";


    public static final String PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID = "2.16.840.1.101.3.7.2.16.24";
    public static final byte[] PAIRING_CODE_REFERENCE_DATA_CONTAINER_TAG = {0x5F, (byte)0xC1, 0x23};
    public static final int PAIRING_CODE_REFERENCE_DATA_CONTAINER_ID = 0x1018;
    public static final String PAIRING_CODE_REFERENCE_DATA_CONTAINER_NAME = "Pairing Code Reference Data Container";


    public static final String[] MandatoryContainers() {
        final String[] rv = {
                CARD_CAPABILITY_CONTAINER_OID,
                CARD_HOLDER_UNIQUE_IDENTIFIER_OID,
                X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID,
                CARDHOLDER_FINGERPRINTS_OID,
                SECURITY_OBJECT_OID,
                CARDHOLDER_FACIAL_IMAGE_OID,
                X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID
        };
        return rv;
    }

    public static final ArrayList<String> AllContainers() {

        ArrayList<String> rv = new ArrayList<String>();
        rv.add(CARD_CAPABILITY_CONTAINER_OID);
        rv.add(CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
        rv.add(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
        rv.add(CARDHOLDER_FINGERPRINTS_OID);
        rv.add(SECURITY_OBJECT_OID);
        rv.add(CARDHOLDER_FACIAL_IMAGE_OID);
        rv.add(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
        rv.add(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
        rv.add(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
        rv.add(PRINTED_INFORMATION_OID);
        rv.add(DISCOVERY_OBJECT_OID);
        rv.add(KEY_HISTORY_OBJECT_OID);
        rv.add(CARDHOLDER_IRIS_IMAGES_OID);
        rv.add(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID);
        rv.add(SECURE_MESSAGING_CERTIFICATE_SIGNER_OID);
        rv.add(PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID);

        return rv;
    }

    public static final HashMap<String, byte[]> oidMAP = new HashMap<String, byte[]>(){
        {
            put(CARD_CAPABILITY_CONTAINER_OID, CARD_CAPABILITY_CONTAINER_TAG);
            put(CARD_HOLDER_UNIQUE_IDENTIFIER_OID, CARD_HOLDER_UNIQUE_IDENTIFIER_TAG);
            put(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_TAG);
            put(CARDHOLDER_FINGERPRINTS_OID, CARDHOLDER_FINGERPRINTS_TAG);
            put(SECURITY_OBJECT_OID, SECURITY_OBJECT_TAG);
            put(CARDHOLDER_FACIAL_IMAGE_OID, CARDHOLDER_FACIAL_IMAGE_TAG);
            put(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_TAG);
            put(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_TAG);
            put(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, X509_CERTIFICATE_FOR_KEY_MANAGEMENT_TAG);
            put(PRINTED_INFORMATION_OID, PRINTED_INFORMATION_TAG);
            put(DISCOVERY_OBJECT_OID, DISCOVERY_OBJECT_TAG);
            put(KEY_HISTORY_OBJECT_OID, KEY_HISTORY_OBJECT_TAG);
            put(CARDHOLDER_IRIS_IMAGES_OID, CARDHOLDER_IRIS_IMAGES_TAG);
            put(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID, BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_TAG);
            put(SECURE_MESSAGING_CERTIFICATE_SIGNER_OID, SECURE_MESSAGING_CERTIFICATE_SIGNER_TAG);
            put(PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID, PAIRING_CODE_REFERENCE_DATA_CONTAINER_TAG);
        }
    };
    public static final HashMap<String, String> oidNameMAP = new HashMap<String, String>(){
        {
            put(CARD_CAPABILITY_CONTAINER_OID, CARD_CAPABILITY_CONTAINER_NAME);
            put(CARD_HOLDER_UNIQUE_IDENTIFIER_OID, CARD_HOLDER_UNIQUE_IDENTIFIER_NAME);
            put(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID, X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_NAME);
            put(CARDHOLDER_FINGERPRINTS_OID, CARDHOLDER_FINGERPRINTS_NAME);
            put(SECURITY_OBJECT_OID, SECURITY_OBJECT_NAME);
            put(CARDHOLDER_FACIAL_IMAGE_OID, CARDHOLDER_FACIAL_IMAGE_NAME);
            put(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID, X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_NAME);
            put(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID, X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_NAME);
            put(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID, X509_CERTIFICATE_FOR_KEY_MANAGEMENT_NAME);
            put(PRINTED_INFORMATION_OID, PRINTED_INFORMATION_NAME);
            put(DISCOVERY_OBJECT_OID, DISCOVERY_OBJECT_NAME);
            put(KEY_HISTORY_OBJECT_OID, KEY_HISTORY_OBJECT_NAME);
            put(CARDHOLDER_IRIS_IMAGES_OID, CARDHOLDER_IRIS_IMAGES_NAME);
            put(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID, BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_NAME);
            put(SECURE_MESSAGING_CERTIFICATE_SIGNER_OID, SECURE_MESSAGING_CERTIFICATE_SIGNER_NAME);
            put(PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID, PAIRING_CODE_REFERENCE_DATA_CONTAINER_NAME);
        }
    };

    public static final HashMap<Integer, String> idMAP = new HashMap<Integer, String>(){
        {
            put(CARD_CAPABILITY_CONTAINER_ID, CARD_CAPABILITY_CONTAINER_OID);
            put(CARD_HOLDER_UNIQUE_IDENTIFIER_ID, CARD_HOLDER_UNIQUE_IDENTIFIER_OID);
            put(X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_ID, X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID);
            put(CARDHOLDER_FINGERPRINTS_ID, CARDHOLDER_FINGERPRINTS_OID);
            put(SECURITY_OBJECT_ID, SECURITY_OBJECT_OID);
            put(CARDHOLDER_FACIAL_IMAGE_ID, CARDHOLDER_FACIAL_IMAGE_OID);
            put(X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_ID, X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID);
            put(X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_ID, X509_CERTIFICATE_FOR_DIGITAL_SIGNATURE_OID);
            put(X509_CERTIFICATE_FOR_KEY_MANAGEMENT_ID, X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID);
            put(PRINTED_INFORMATION_ID, PRINTED_INFORMATION_OID);
            put(DISCOVERY_OBJECT_ID, DISCOVERY_OBJECT_OID);
            put(KEY_HISTORY_OBJECT_ID, KEY_HISTORY_OBJECT_OID);
            put(CARDHOLDER_IRIS_IMAGES_ID, CARDHOLDER_IRIS_IMAGES_OID);
            put(BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_ID, BIOMETRIC_INFORMATION_TEMPLATES_GROUP_TEMPLATE_OID);
            put(SECURE_MESSAGING_CERTIFICATE_SIGNER_ID, SECURE_MESSAGING_CERTIFICATE_SIGNER_OID);
            put(PAIRING_CODE_REFERENCE_DATA_CONTAINER_ID, PAIRING_CODE_REFERENCE_DATA_CONTAINER_OID);
        }
    };

    public static final String getKeyManagmentCertOID(int number){

        String firstPart = "2.16.840.1.101.3.7.2.16.";
        String oid = firstPart + Integer.toString(number);

        return oid;
    }

    public static final String getKeyManagmentCertName(int number){

        String firstPart = "Retired X.509 Certificate for Key Management ";
        String name = firstPart + Integer.toString(number);

        return name;
    }

    public static final byte[] getKeyManagmentCertTag(int number){

        int firstPart = 0x5FC10C;
        int tag = firstPart + number;

        byte[] arr = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(tag).array(), 1, 4);

        return arr;
    }


    public static final byte[] getKeyManagmentCertID(int number){

        int firstPart = 0x1000;
        int tag = firstPart + number;

        byte[] arr = Arrays.copyOfRange(ByteBuffer.allocate(4).putInt(tag).array(), 1, 4);

        return arr;
    }


}
