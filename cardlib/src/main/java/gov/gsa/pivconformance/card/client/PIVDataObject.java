package gov.gsa.pivconformance.card.client;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.tlv.BerTag;

/**
 * Represents a PIV data object as read to or written from the card.
 * Subclasses may provide abstractions for field access.
 */
public class PIVDataObject {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PIVDataObject.class);

    private byte[] m_dataBytes;
    private String m_OID;
    private boolean m_signed;
    protected List<BerTag> m_tagList;

    /**
     * Initialize an invalid PIV data object
     */
    public PIVDataObject() {

        m_OID = null;
        m_signed = false;
        m_tagList = new ArrayList();
    }

    /**
     *
     * Constructor that creates a specific PIV data object based on the passed in OID
     *
     * @param OID String containing OID identifying PIV data object
     */
    public PIVDataObject(String OID) {
        m_OID = OID;
    }

    /**
     *
     * Sets the raw PIV data object value
     *
     * @param dataBytes Byte array containing raw PIV data object value
     */
    public void setBytes(byte[] dataBytes) {
        m_dataBytes = dataBytes;
    }

    /**
     *
     * Returns the raw PIV data object value
     *
     * @return Byte array containing raw PIV data object value
     */
    public byte[] getBytes() { return m_dataBytes; }

    /**
     *
     * Returns a string with the OID that identifies PIV data object
     *
     * @return String containing the OID that identifies PIV data object
     */
    public String getOID() {
        return m_OID;
    }


    /**
     *
     * Sets the OID that identifies PIV data object
     *
     * @param OID String containing the OID that identifies PIV data object
     */
    public void setOID(String OID) {
        m_OID = OID;
    }


    /**
     *
     * Returns friendly  name of PIV data object
     *
     * @return String containing the friendly  name of PIV data object
     */
    public String getFriendlyName() {
        return APDUConstants.oidNameMAP.getOrDefault(m_OID, "Undefined");
    }

    /**
     *
     * Returns the tag value for the current PIV data object
     *
     * @return Byte array containing tag value of the current PIV data object
     */
    public byte[] getTag() {
        byte[] rv = APDUConstants.oidMAP.getOrDefault(m_OID, new byte[]{});
        return rv;
    }

    /**
     *
     * Place holder that will throw RuntimeError if the is a missing implementations of decode
     *
     * @return false
     */
    public boolean decode() {
        // XXX *** make this throw a RuntimeError once implementations are notionally in place
        s_logger.error("decode() called without a concrete implementation.");
        return false;
    }

    /**
     *
     * Returns a String containing hex representation of the raw value of the PIV data object
     *
     * @return String containing hex representation of the raw value of the PIV data object
     */
    public String toRawHexString() {
        return Hex.encodeHexString(m_dataBytes);
    }

    /**
     *
     * Returns a String containing PIV data object OID, friendly name and hex representation of the raw value of the PIV data object
     *
     * @return String containing PIV data object OID, friendly name and hex representation of the raw value of the PIV data object
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PIV Data Object with OID " + m_OID + " (" + getFriendlyName() + "):");
        sb.append(toRawHexString());
        return sb.toString();
    }

    /**
     *
     * Sets a boolean value inficating if the PIV data object is signed
     *
     * @param signed True if signed, false otherwise
     */
    public void setSigned(boolean signed) {
        m_signed = signed;
    }

    /**
     *
     * Returns true if the PIV data object is signed
     *
     * @return True if the PIV data object is signed
     */
    public boolean isSigned() {
        return m_signed;
    }
    
    /**
    *
    * Returns the list of tags in order for the PIV data object
    *
    * @return Returns the list of tags in order for the PIV data object
    */
    public List<BerTag> getTagList() {
		return m_tagList;
	}

    /**
    *
    * Sets the list of tags in order for the PIV data object
    *
    * @return Set the list of tags in order for the PIV data object
    */
	public void setTagList(List<BerTag> tagList) {
		this.m_tagList = tagList;
	}
}
