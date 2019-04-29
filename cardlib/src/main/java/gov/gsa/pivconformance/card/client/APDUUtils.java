package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.TagConstants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

/**
 *
 * Helper class that facilitates creation of APDU values
 *
 */
public class APDUUtils {
    private static byte[] s_pivSelect = null;
    private static final Logger s_logger = LoggerFactory.getLogger(APDUUtils.class);

    /**
     *
     * Return APDU value for SELECT card operation
     *
     * @return Byte array with SELECT APDU
     */
    public static byte[] PIVSelectAPDU() {
        if(s_pivSelect == null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.SELECT);
                byte[] p1p2 = {0x04, 0x00};
                baos.write(p1p2);
                baos.write((byte) APDUConstants.PIV_APPID.length);
                baos.write(APDUConstants.PIV_APPID);
                s_pivSelect = baos.toByteArray();
            } catch(IOException ioe) {
                // if we ever hit this, OOM is coming soon
                s_logger.error("Unable to populate static PIV select APDU field.", ioe);
                s_pivSelect = new byte[0];
            }
        }
        return s_pivSelect;
    }

    /**
     *
     * Return APDU value for SELECT card operation based on a specific APP ID value
     *
     * @param appid Byte array with APP ID
     * @return Byte array with SELECT APDU
     */
    public static byte[] PIVSelectAPDU(byte[] appid) {
        byte[] rv_pivSelect = null;
        if(rv_pivSelect == null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.SELECT);
                byte[] p1p2 = {0x04, 0x00};
                baos.write(p1p2);
                baos.write(appid.length);
                baos.write(appid);
                byte[] Le = {0x00};
                baos.write(Le);
                rv_pivSelect = baos.toByteArray();
            } catch(IOException ioe) {
                // if we ever hit this, OOM is coming soon
                s_logger.error("Unable to populate static PIV select APDU field.", ioe);
                rv_pivSelect = new byte[0];
            }
        }
        return rv_pivSelect;
    }

    /**
     *
     * Return APDU value for GENERATE card operation based on a specific APP ID value
     *
     * @param keyReference Byte value identifying key reference of the generated key pair
     * @param cryptoMechanism Byte value identifying the type of key pair to be generated
     * @param parameter Byte array containing the parameter value
     * @return Byte array with GENERATE APDU
     */
    public static byte[] PIVGenerateKeyPairAPDU(byte keyReference, byte cryptoMechanism, byte[] parameter) {
        byte[] rv_pivGenerate = null;
        if(rv_pivGenerate == null) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(APDUConstants.COMMAND);
                baos.write(APDUConstants.GENERATE);
                byte[] p1 = {0x00};
                baos.write(p1);
                baos.write(keyReference);

                //If parameter is present data length will be 1 (Tag 'AC') + length + 1 (cryptographic mechanism tag) + 1 (length) + 1 (cryptographic mechanism) + 1 (parameter tag) + parameter length length+ parameter length .
                //If parameter is absent data length will be 1 (Tag 'AC') + length + 1 (cryptographic mechanism tag) + 1 (cryptographic mechanism length) + 1 (cryptographic mechanism)
                if(parameter != null) {
                    baos.write(1 + 1 + 1 + 1 + 1 + 1 + 1 + parameter.length);
                }
                else {
                    baos.write(1 + 1 + 1 + 1 + 1);
                }

                //Write Control reference template tag
                baos.write(APDUConstants.CONTROL_REFERENCE_TEMPLATE_TAG);

                //Write length value for Control reference template

                if(parameter != null)  {

                    //Add length of Crypto Mechanism TLV
                    baos.write(3 + 2 + parameter.length);

                }
                else {

                    //Add length of Crypto Mechanism TLV
                    baos.write(3);
                }

                baos.write(TagConstants.CRYPTO_MECHANISM_TAG);
                //Add length of crypto mechanism which will be 1
                baos.write(1);
                baos.write(cryptoMechanism);
                if(parameter != null)  {
                    byte[] parameterTag = {TagConstants.PARAMETER_TAG};
                    baos.write(parameterTag);
                    baos.write(parameter.length);
                    baos.write(parameter);
                }
                byte[] Le = {0x00};
                baos.write(Le);
                rv_pivGenerate = baos.toByteArray();
            } catch(IOException ioe) {
                // if we ever hit this, OOM is coming soon
                s_logger.error("Unable to populate static PIV Generate APDU field.", ioe);
                rv_pivGenerate = new byte[0];
            }
        }
        return rv_pivGenerate;
    }

    /**
     *
     * @param data
     * @return
     */
    public static byte[] PIVGetDataAPDU(byte[] data) {

        byte[] rv_pivGetData = null;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(APDUConstants.COMMAND);
            baos.write(APDUConstants.GET);
            byte[] p1p2 = {0x3f, (byte) 0xff};
            baos.write(p1p2);
            byte[] Lc = {(byte)(data.length & 0xff)};
            baos.write(Lc);
            baos.write(data);
            byte[] Le = {0x00};
            baos.write(Le);
            rv_pivGetData = baos.toByteArray();
        } catch(IOException ioe) {
            // if we ever hit this, OOM is coming soon
            s_logger.error("Unable to populate PIV get data APDU field.", ioe);
            rv_pivGetData = new byte[0];
        }

        return rv_pivGetData;
    }
    /**
     * 
     * @param data
     * @return
     */
    public static byte[] PIVGetDataAPDU_Broken(byte[] data) {

        byte[] rv_pivGetData = null;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(APDUConstants.COMMAND);
            baos.write(APDUConstants.GET);
            byte[] p1p2 = {0x3f, (byte) 0xff};
            baos.write(p1p2);
            byte[] Lc = {(byte)(data.length & 0xff)};
            baos.write(Lc);
            baos.write(data);
            byte[] Le = {0x08};
            baos.write(Le);
            rv_pivGetData = baos.toByteArray();
        } catch(IOException ioe) {
            // if we ever hit this, OOM is coming soon
            s_logger.error("Unable to populate PIV get data APDU field.", ioe);
            rv_pivGetData = new byte[0];
        }

        return rv_pivGetData;
    }

    /**
     *
     * Helper fuction that converts byte[] into unsigned int
     *
     * @param b Byte array to be converter to unsigned int
     * @return Unsigned int value
     */
    public static final int bytesToInt(byte[] b) {

        if(b.length != 2){
            throw new IllegalArgumentException("Invalid buffer length passed in.");
        }

        int l = 0;
        l |= b[0] & 0xFF;
        l <<= 8;
        l |= b[1] & 0xFF;
        return l;
    }

    /**
     *
     * Helper function that constructs a TLV buffer based on passed in tag and value buffer
     *
     * @param tag  Byte array with tag info
     * @param value Byte array with value
     * @return Byte array with resulting TLV value
     */
    public static final byte[] getTLV(byte[] tag, byte[] value) {

        if(tag == null || value == null)
            throw new IllegalArgumentException("Null buffer passed into getTLV().");
        byte[] rv = null;
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int numberLenBytes = (value == null) ? 0 : (value.length > 127) ? 2 : 1;
        try {
            // Tag
            os.write(tag);
            // Length & value
            if (numberLenBytes == 2) {
                os.write((byte) ((0x80 + numberLenBytes) & 0xff));
                os.write((byte) (((value.length & 0xff00) >> 8) & 0xff));
                os.write((byte) (value.length & 0x00ff));
                os.write(value);
            } else if (numberLenBytes == 1) {
                os.write((byte) (value.length & 0xff));
                os.write(value);
            } else if (numberLenBytes == 0) {
                os.write(0x00);
            }
        } catch (IOException e) {
            s_logger.error("Failed to create TLV value: {}" , e.getMessage());
            return rv;
        }

        rv = os.toByteArray();
        return rv;
    }

    /**
     *
     * Helper function that creates ASN1ObjectIdentifier object based on OID value and a service name
     *
     * @param serviceName String value identifying the service
     * @param name String value identifying OID by name
     * @return
     */
    public static ASN1ObjectIdentifier getAlgorithmIdentifier(String serviceName, String name) {
        ASN1ObjectIdentifier oid = null;
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        Provider.Service service = provider.getService(serviceName, name);
        if (service != null) {
            String string = service.toString();
            String array[] = string.split("\n");
            if (array.length > 1) {
                string = array[array.length - 1];
                array = string.split("[\\[\\]]");
                if (array.length > 2) {
                    string = array[array.length - 2];
                    array = string.split(", ");
                    Arrays.sort(array);
                    oid = new ASN1ObjectIdentifier(array[0]);
                }
            }
        }
        return oid;
    }
}
