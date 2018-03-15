package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerId;

public class SecurityObject extends PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(SecurityObject.class);
    private byte[] m_mapping;
    private byte[] m_so;
    private List<String> m_containerIDList;
    private CMSSignedData m_signedData;;

    public SecurityObject() {
        m_mapping = null;
        m_so = null;
        m_signedData = null;
        m_containerIDList = null;
    }

    public byte[] getMapping() {
        return m_mapping;
    }

    public void setMapping(byte[] mapping) {
        m_mapping = mapping;
    }

    public byte[] getSecurityObject() {
        return m_so;
    }

    public void setSecurtiyObject(byte[] so) {
        m_so = so;
    }

    public CMSSignedData getSignedData() {
        return m_signedData;
    }

    public void setSignedData(CMSSignedData signedData) {
        m_signedData = signedData;
    }


    public List<String> getContainerIDList() {
        return m_containerIDList;
    }

    public void setContainerIDList(List<String> containerIDList) {
        m_containerIDList = containerIDList;
    }

    public static List<byte[]> divideArray(byte[] source, int chunksize) {

        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }

        return result;
    }

    public boolean decode() {

        try {
            byte[] rawBytes = this.getBytes();
            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlvs outer = tlvp.parse(rawBytes);
            List<BerTlv> outerTlvs = outer.getList();
            if (outerTlvs.size() == 1 && outerTlvs.get(0).isTag(new BerTag(0x53))) {
                byte[] tlvBuf = outerTlvs.get(0).getBytesValue();
                outer = tlvp.parse(tlvBuf);
            }
            for (BerTlv tlv : outer.getList()) {
                byte[] tag = tlv.getTag().bytes;
                if (Arrays.equals(tag, TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG)) {
                    m_mapping = tlv.getBytesValue();

                    if(m_mapping == null){
                        s_logger.error("Missing mapping of DG to contains IDs for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    //Break the byte array into chunks of 3
                    List<byte[]> idList = divideArray(m_mapping,3);

                    //Iterate over the resulting list to get container IDs for each
                    for(byte[] b : idList)
                    {
                        if(m_containerIDList == null)
                            m_containerIDList = new ArrayList<String>();

                        byte[] tg = Arrays.copyOfRange(b, 1, 3);
                        int i = (int) APDUConstants.bytesToInt(tg);
                        String cc = APDUConstants.idMAP.get(i);

                        //Add the container oid to the list will be easier to look up.
                        m_containerIDList.add(cc);
                    }


                } else if (Arrays.equals(tag, TagConstants.SECURITY_OBJECT_TAG)) {
                    m_so = tlv.getBytesValue();

                    if(m_so == null){
                        s_logger.error("Missing security object value for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    //Decode the ContentInfo and get SignedData object.
                    ByteArrayInputStream bIn = new ByteArrayInputStream(m_so);
                    ASN1InputStream      aIn = new ASN1InputStream(bIn);
                    ContentInfo ci = ContentInfo.getInstance(aIn.readObject());
                    m_signedData = new CMSSignedData(ci);

                } else {
                    if (!Arrays.equals(tag, TagConstants.ERROR_DETECTION_CODE_TAG) && tlv.getBytesValue().length != 0) {
                        s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                    }
                }
            }
        }
        catch (Exception e)
        {
            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage());
        }
        return true;
    }

}
