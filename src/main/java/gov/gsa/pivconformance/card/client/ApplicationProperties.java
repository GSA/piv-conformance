package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

/**
 * Encapsulates the application properties record for a PIV application, as described in SP800-73-4 part 2, table 3
 */
public class ApplicationProperties {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ApplicationProperties.class);

    private byte[] m_appPropertiesBytes;
    private String m_url;
    private String m_appLabel;
    private byte[] m_cryptoAlgs;
    private byte[] m_coexistentTagAllocationAuthority;
    private byte[] m_appID;

    public ApplicationProperties() {

        m_appPropertiesBytes = null;
        m_url = "";
        m_appLabel = "";
        m_cryptoAlgs = null;
        m_coexistentTagAllocationAuthority = null;
        m_appID = null;
    }


    public void setBytes(byte[] appPropertiesBytes) {

        m_appPropertiesBytes = appPropertiesBytes;

        try
        {
            BerTlvParser parser = new BerTlvParser();
            BerTlvs tlvs = parser.parse(appPropertiesBytes, 0, appPropertiesBytes.length);


            BerTag berAIDTag = new BerTag(TagConstants.AID_TAG);
            BerTag berAppLabelTag = new BerTag(TagConstants.APPLICATION_LABEL);
            BerTag berURLTag = new BerTag(TagConstants.UNIFORM_RESOURCE_LOCATOR);
            BerTag berCryptAlgsTag = new BerTag(TagConstants.CRYPTOGRAPHIC_ALGORITHMS);
            BerTag berCoexistentTagAllocationAuthorityTag = new BerTag(TagConstants.COEXISTENT_TAG_ALLOCATION_AUTHORITY);

            BerTlv aidTlv = tlvs.find(berAIDTag);
            BerTlv appLabelTlv = tlvs.find(berAppLabelTag);
            BerTlv urlTlv = tlvs.find(berURLTag);
            BerTlv CryptAlgsTlv = tlvs.find(berCryptAlgsTag);
            BerTlv CoexistentTagAllocationAuthorityTlv = tlvs.find(berCoexistentTagAllocationAuthorityTag);

            if(aidTlv != null){
                m_appID = aidTlv.getBytesValue();
            }

            if(appLabelTlv != null){
                m_appLabel = new String(appLabelTlv.getBytesValue());
            }

            if(urlTlv != null){
                m_url = new String(urlTlv.getBytesValue());
            }

            if(CryptAlgsTlv != null){
                m_cryptoAlgs = CryptAlgsTlv.getBytesValue();
            }

            if(CoexistentTagAllocationAuthorityTlv != null){
                List<BerTlv> berTlvsList = CoexistentTagAllocationAuthorityTlv.getValues();
                for(BerTlv tlv : berTlvsList) {
                    if(tlv.isPrimitive() && tlv.isTag(berAIDTag)) {
                        m_coexistentTagAllocationAuthority = tlv.getBytesValue();
                    }
                }
            }

        }catch (Exception ex) {

            s_logger.info("Unable to parse application properties data structure: {}", ex.getMessage());
        }
    }

    public byte[] getBytes() {
        return m_appPropertiesBytes;
    }

    public String getURL() {
        return m_url;
    }

    public String getAppLabel() {
        return m_appLabel;
    }

    public byte[] getCryptoAlgs() {
        return m_cryptoAlgs;
    }

    public byte[] getCoexistentTagAllocationAuthority() {
        return m_coexistentTagAllocationAuthority;
    }

    public byte[] getAppID() {
        return m_appID;
    }

}
