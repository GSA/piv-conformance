package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.icao.DataGroupHash;
import org.bouncycastle.asn1.icao.LDSSecurityObject;
import org.bouncycastle.cms.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.util.*;
import java.io.ByteArrayInputStream;

import org.bouncycastle.asn1.cms.ContentInfo;

/**
 *
 * Encapsulates a Security Object data object  as defined by SP800-73-4 Part 2 Appendix A Table 12
 *
 */
public class SecurityObject extends SignedPIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(SecurityObject.class);
    private byte[] m_mapping;
    private byte[] m_so;
    private HashMap<Integer, String> m_containerIDList;
    HashMap<String, byte[]> m_mapOfDataElements;
    HashMap<Integer, byte[]> m_dghList;
    private boolean m_errorDetectionCode;

    /**
     * SecurityObject class constructor, initializes all the class fields.
     */
    public SecurityObject() {
        m_mapping = null;
        m_so = null;
        m_containerIDList = null;
        m_mapOfDataElements = null;
        m_dghList = null;
        m_errorDetectionCode = false;
        m_content = new HashMap<BerTag, byte[]>();
    }

    /**
     * Returns boolean value indicating if error detection code is present
     *
     * @return Boolean value indicating if error detection code is present
     */
    public boolean getErrorDetectionCode() {

        return m_errorDetectionCode;
    }

    public HashMap<String, byte[]> getMapOfDataElements() {
        return m_mapOfDataElements;
    }

    public void setMapOfDataElements(HashMap<String, byte[]> mapOfDataElements) {
        m_mapOfDataElements = mapOfDataElements;
    }

    /**
     *
     * Returns byte array containing Mapping of DG to ContainerID
     *
     * @return Byte array containing Mapping of DG to ContainerID
     */
    public byte[] getMapping() {
        return m_mapping;
    }

    /**
     *
     * Sets the Mapping of DG to ContainerID
     *
     * @param mapping Byte array containing Mapping of DG to ContainerID
     */
    public void setMapping(byte[] mapping) {
        m_mapping = mapping;
    }

    /**
     *
     * Returns byte array containing security object
     *
     * @return Byte array containing security object value
     */
    public byte[] getSecurityObject() {
        return m_so;
    }

    /**
     *
     * Sets the security object value
     *
     * @param so Byte array containing security object value
     */
    public void setSecurtiyObject(byte[] so) {
        m_so = so;
    }

    /**
     *
     * Returns a map containing container ID list
     *
     * @return HashMap containing container ID list
     */
    public HashMap<Integer, String> getContainerIDList() {
        return m_containerIDList;
    }

    /**
     *
     * Sets the Hash map with containing container ID list
     *
     * @param containerIDList HashMap containing container ID list
     */
    public void setContainerIDList(HashMap<Integer, String> containerIDList) {
        m_containerIDList = containerIDList;
    }

    //XXX Move this

    /**
     *
     * Helper function to divide a byte array into n numer of chuncks
     *
     * @param source  Byte array to be divided
     * @param chunksize Integer specifying number of chanks
     * @return List of byte arrays
     */
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

    /**
     *
     * Decode function that decodes Security Object retrieved from the card and populates various class fields.
     *
     * @return True if decode was successful, false otherwise
     */
    public boolean decode() {
        SignerInformationStore signers = null;
        SignerInformation signer = null;
        try {
        	super.m_tagList.clear();
            byte[] rawBytes = this.getBytes();
            s_logger.debug("rawBytes: {}", Hex.encodeHexString(rawBytes));
            BerTlvParser tlvp = new BerTlvParser(new CCTTlvLogger(this.getClass()));
            BerTlvs outer = tlvp.parse(rawBytes);
            List<BerTlv> outerTlvs = outer.getList();
            if (outerTlvs.size() == 1 && outerTlvs.get(0).isTag(new BerTag(0x53))) {
                byte[] tlvBuf = outerTlvs.get(0).getBytesValue();
                outer = tlvp.parse(tlvBuf);
            }
            for (BerTlv tlv : outer.getList()) {
            	s_logger.debug("SecurityObject: processing tag {}", tlv.getTag().toString());
                byte[] tag = tlv.getTag().bytes;

            	super.m_tagList.add(tlv.getTag());
                if (Arrays.equals(tag, TagConstants.MAPPING_OF_DG_TO_CONTAINER_ID_TAG)) {
                    m_mapping = tlv.getBytesValue();
                    m_content.put(tlv.getTag(), tlv.getBytesValue());

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
                            m_containerIDList = new HashMap<Integer, String>();

                        byte idByte = b[0];
                        byte[] tg = Arrays.copyOfRange(b, 1, 3);
                        int i = (int) APDUUtils.bytesToInt(tg);
                        String cc = APDUConstants.idMAP.get(i);

                        int tmp = idByte;
                        Integer id = tmp;
                        //Add the container oid to the list will be easier to look up.
                        m_containerIDList.put(id, cc);
                    }
                } else if (Arrays.equals(tag, TagConstants.SECURITY_OBJECT_TAG)) {
                    m_so = tlv.getBytesValue();
                    m_content.put(tlv.getTag(), tlv.getBytesValue());

                    if(m_so == null){
                        s_logger.error("Missing security object value for {}.", APDUConstants.oidNameMAP.get(super.getOID()));
                        return false;
                    }

                    //Decode the ContentInfo and get SignedData object.
                    ByteArrayInputStream bIn = new ByteArrayInputStream(m_so);
                    ASN1InputStream      aIn = new ASN1InputStream(bIn);
                    
                    // Set the ContentInfo structure in super class
                    setContentInfo(ContentInfo.getInstance(aIn.readObject())); aIn.close();
                    // Set the CMSSignedData object
                    setAsymmetricSignature(new CMSSignedData(getContentInfo()));
                    // This gets set in case hasOwnSignerCert() is false
                    setSignedContent(m_so);
                    // Indicate this object needs a signature verification
                    setSigned(true);

                    CMSSignedData cmsSignedData = getAsymmetricSignature();                    

                    signers = cmsSignedData.getSignerInfos();

                    for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                        signer = i.next();                               
                    }

                    // Grab last signed digest
                    setSignedAttrsDigest(signers);
                    // Precompute digest but don't compare -- let consumers do that so they can throw their own
                    // exception
                    setComputedDigest(signer, m_so);

                } else {
                    if (!Arrays.equals(tag, TagConstants.ERROR_DETECTION_CODE_TAG) && tlv.getBytesValue().length != 0) {
                        s_logger.warn("Unexpected tag: {} with value: {}", Hex.encodeHexString(tlv.getTag().bytes), Hex.encodeHexString(tlv.getBytesValue()));
                    }
                    else{
                        m_errorDetectionCode = true;
                    }
                }
            }
        }
        catch (Exception e)
        {
            s_logger.error("Error parsing {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), e.getMessage(), e);
            return false;
        }

        if (m_mapping == null || m_so == null)
            return false;

        return true;
    }

    /**
     *
     * Verifies all included hashes
     *
     * @return True if all hashes match, false otherwise
     */
    public boolean verifyHashes() {
        boolean rv_result = true;

        try {

            if(m_dghList == null) {
                if (m_mapOfDataElements == null) {
                    s_logger.error("Missing list of objects to hash");
                    return false;
                }

                CMSSignedData s = new CMSSignedData(getContentInfo());

                ASN1InputStream asn1is = new ASN1InputStream(new ByteArrayInputStream((byte[]) s.getEncoded()));
                ASN1Sequence soSeq;
                soSeq = (ASN1Sequence) asn1is.readObject();
                asn1is.close();
                LDSSecurityObject ldsso = LDSSecurityObject.getInstance(soSeq);

                DataGroupHash [] dghList = ldsso.getDatagroupHash();

                m_dghList = new HashMap<Integer, byte[]>();
                for (DataGroupHash entry : dghList) {
                    m_dghList.put(entry.getDataGroupNumber(), entry.getDataGroupHashValue().getOctets());
                }
            }

            for (Map.Entry<Integer, byte[]> entry : m_dghList.entrySet()) {

                String oid = m_containerIDList.get(entry.getKey());
                s_logger.debug("Checking digest for {} (0x{})", oid, Integer.toHexString(entry.getKey()));

                if(oid == null) {
                    s_logger.error("Missing object to hash for id {}: ", entry.getKey());
                    return false;
                }

                byte[] bytesToHash = m_mapOfDataElements.get(oid);
                s_logger.debug("Bytes to hash: {}", Hex.encodeHexString(bytesToHash));

                MessageDigest md = MessageDigest.getInstance(APDUConstants.DEFAULTHASHALG);
                md.update(bytesToHash);
                byte[] digest = md.digest();
                s_logger.debug("Digest: {}", Hex.encodeHexString(digest));
                
                if (!Arrays.equals(entry.getValue(), digest)) {
                	s_logger.error("hashes don't match in security object (reference length: {}, calculated length: {})", entry.getValue().length, digest.length);
                    s_logger.error("reference: {}, calculated: {}", Hex.encodeHexString(entry.getValue()), Hex.encodeHexString(digest));
                	rv_result = false;
                }
                s_logger.debug("rv_result is currently {}", rv_result);
            }

        } catch (Exception ex) {
            s_logger.error("Error verifying hash  on {}: {}", APDUConstants.oidNameMAP.get(super.getOID()), ex.getMessage());
        }

        return rv_result;
    }

    /**
     * Verifies hash of a specific container identified by the conteiner ID value
     *
     * @param id Container ID value
     * @return True if hash value included in the security object for the specified container matches hashed value of the container data.
     */
    public boolean verifyHash(Integer id){
        boolean rv_result = true;

        String oid = m_containerIDList.get(id);

        if (oid == null) {
            s_logger.error("Missing object to hash for ID {}: ", id);
            return false;
        }
        
        try {
            CMSSignedData s = new CMSSignedData(getContentInfo());

            if(m_dghList == null) {
                if (m_mapOfDataElements == null) {
                    s_logger.error("Missing list of objects to hash");
                    return false;
                }

                ASN1InputStream asn1is = new ASN1InputStream(new ByteArrayInputStream((byte[]) s.getEncoded()));
                ASN1Sequence soSeq;
                soSeq = (ASN1Sequence) asn1is.readObject();
                asn1is.close();
                LDSSecurityObject ldsso = LDSSecurityObject.getInstance(soSeq);

                DataGroupHash [] dghList = ldsso.getDatagroupHash();

                m_dghList = new HashMap<Integer, byte[]>();
                for (DataGroupHash entry : dghList) {
                    m_dghList.put(entry.getDataGroupNumber(), entry.getDataGroupHashValue().getOctets());
                }
            }

            byte[] bytesToHash = m_mapOfDataElements.get(oid);
            
			String aName = APDUConstants.DEFAULTHASHALG;
            SignerInformationStore signers = s.getSignerInfos();
            for (Iterator<SignerInformation> i = signers.getSigners().iterator(); i.hasNext();) {
                SignerInformation signer = i.next();
                aName = signer.getDigestAlgOID();
                break;
            }
 
            MessageDigest md = MessageDigest.getInstance(aName);
            md.update(bytesToHash);
            byte[] digest = md.digest();

            if (!Arrays.equals(m_dghList.get(id), digest)) {
                rv_result = false;
            }

        } catch (Exception ex) {
            s_logger.error("Error verifying hash for ID: {}", id);
        }

        return rv_result;
    }


    /**
     * Returns true if a specified container identified by the oid is covered by one of the hashes in the map.
     *
     * @param oid String identifying container to look up
     * @return True if specified container is covered by one of the hashes in the map, false otherwise
     */
    public boolean hashIncluded(String oid){

        boolean rv = false;


        if(m_containerIDList.containsValue(oid))
            rv = true;

        return rv;
    }

}
