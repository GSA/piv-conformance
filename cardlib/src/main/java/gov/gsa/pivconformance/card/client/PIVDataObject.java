package gov.gsa.pivconformance.card.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.tlv.BerTag;
import gov.gsa.pivconformance.tlv.HexUtil;
import gov.gsa.pivconformance.tlv.TagBoundaryManager;

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
    private boolean m_mandatory;
    private boolean m_requiresPin;
    protected List<BerTag> m_tagList;
    private boolean m_error_Detection_Code;
    private boolean m_error_Detection_Code_Has_Data;
    private TagBoundaryManager m_tagLengthRules = DataModelSingleton.getInstance().getLengthRules();
    private boolean m_lengthOk;
    // TODO: Cache these tags
    protected HashMap<BerTag, byte[]> m_content;
    private String m_name;
    private static List<String> m_oidList = new ArrayList<String>();
	private String m_containerName;
	
    /**
     * Initialize an invalid PIV data object
     */
    public PIVDataObject() {

        m_OID = null;
        m_signed = false;
        m_mandatory = false;
        m_requiresPin = false;
        m_tagList = new ArrayList<BerTag>();
        m_lengthOk = false;
        m_content = new HashMap<BerTag, byte[]>();
        m_name = null;
		m_containerName = null;
    }

    /**
     *
     * Constructor that creates a specific PIV data object based on the passed in OID
     *
     * @param OID String containing OID identifying PIV data object
     */
    public PIVDataObject(String OID) {
        setOID(OID);
        setMandatory(APDUConstants.isContainerMandatory(m_OID));
        setContainerName(APDUConstants.containerOidToNameMap.get(m_OID));
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
        return APDUConstants.oidNameMap.getOrDefault(m_OID, "Undefined");
    }

   /**
    * Indicates whether the object associated with the subclass
    * is mandatory.
    */
   
   public boolean isMandatory(String oid) {
	   return m_mandatory;
   }
   
   /**
    * Indicates whether the object associated with the subclass
    * is mandatory.
    */
   
   public void setMandatory(boolean flag) {
	   m_mandatory = flag;
   }
   /**
    * Indicates whether the object associated with the subclass
    * is requires a pin.
    */
   
   public boolean requiresPin(String oid) {
	   return m_requiresPin;
   } 
   
   /**
    * Sets the flag indicating that this container OID requires a PIN to access
    * 
    */
   
   public void setRequiresPin(boolean required) {
	   m_requiresPin = required;
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
	 * Indicates whether the given length is within boundaries of the rule
	 * 
	 * @param tag the tag 
	 * @param valueLen the value, as counted by byte[].length
	 * @return true if the value meets all length requirements for that tag
	 * @throws Exception 
	 */

    private boolean inBounds(String name, BerTag tag, int valueLen) throws Exception {
    	try {
        	int diff = m_tagLengthRules.lengthDelta(name, tag, valueLen);
	    	if (diff != 0) {
	    		String tagString = HexUtil.toHexString(tag.bytes);
	    		String errStr = (String.format("Tag %s length was %d bytes, differs from 800-73 spec by %d", tagString, valueLen, diff));
	    		Exception e = new TagBoundaryException(errStr);
	    		throw(e);
	    	}
    	} catch (CardClientException e) { return false; }

    	return true;
    }
    
	/**
	 * Indicates whether the given length is within boundaries of the rule
	 * 
	 * @param oid the container OID 
	 * @return true if all tags in the container meet the length requirements for that tag 
	 * and false if the length is greater than the high bound.
	 * For rules that require either of two values, the value returned indicates which of
	 * the two values matched with a 0x10 or 0x01 (low or high).
	 * @throws Exception 
	 */
    public boolean inBounds(String oid) throws Exception {
    	String name = APDUConstants.oidNameMap.get(oid);
    	if (name == null) {
    		return false;
    	}
    	// Iterate over each tag and corresponding value
    	Iterator<Map.Entry<BerTag, byte[]>> it = m_content.entrySet().iterator();
        while (it.hasNext()) {
            Entry<BerTag, byte[]> pair = it.next();
            BerTag tag = (BerTag) pair.getKey();
            byte value[] = (byte[]) pair.getValue();
            // Check length
            if (!(this.m_lengthOk = this.inBounds (name, tag, value.length))) {
            	return false;
            }
        }
        return true;
    }   
 
    public void dump(Class<?> classz) {
        if (m_oidList.indexOf(m_OID) < 0) {
        	m_oidList.add(m_OID);
        	// Get the container name
        	String canonicalName = classz.getCanonicalName();
        	String containerName = getContainerName();
        	String className = containerName == null ? canonicalName : classz.getPackage().toString().replace("package ", "") + "." + containerName;
        	
        	Logger s_containerLogger = LoggerFactory.getLogger(className);
        	s_containerLogger.debug("Container: {}", APDUConstants.oidNameMap.get(m_OID).replace(" ",  "_"));
        	s_containerLogger.debug("Raw bytes: {}", Hex.encodeHexString(m_dataBytes));
        	for (int i = 0; i < m_tagList.size(); i++) {
        		BerTag tag = m_tagList.get(i);
        		if (tag == null) {
        			s_containerLogger.warn("Tag[{}] is null", i);
        		} else if (m_content.get(tag) == null) {
        			s_containerLogger.warn("Tag[{}] ({}) is null", i, Hex.encodeHexString(tag.bytes));
        		} else {
        			s_containerLogger.debug("Tag {}: {}", Hex.encodeHexString(tag.bytes), Hex.encodeHexString(m_content.get(tag)));
        		}
        	}
        }
    	setContainerName(null);
    }
	
	/**
	 * Gets the precomputed message digest of the content
	 * 
	 * @return bytes in the digest
	 */

    /**
     *
     * Place holder that will throw RuntimeError if the is a missing implementations of decode
     *
     * @return false
     */
    public boolean decode() {
        // XXX *** make this throw a RuntimeError once implementations are notionally  in place
        s_logger.error("decode() called without a concrete implementation.");
        return false;
    }

    /**
     *
     * Returns the length of all containers was found to be okay, false otherwise
     *
     * @return True if the length of all containers was found to be okay, false otherwise
     */
    public boolean lengthOk() {
        return m_lengthOk;
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
     * Sets a boolean value indicating if the PIV data object is signed
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

    /**
     * Returns boolean value indicating if error detection code had any bytes
     *
     * @return Boolean value indicating if error detection code had any bytes
     */
	
    public boolean getErrorDetectionCodeHasData() {
		return m_error_Detection_Code_Has_Data;
	}
  
    public void setErrorDetectionCodeHasData(boolean hasData) {
		m_error_Detection_Code_Has_Data = hasData;
    }
       
    public void setErrorDetectionCode(boolean present) {
    	m_error_Detection_Code = present;
    }

    /**
     * Returns boolean value indicating if error detection code is present
     *
     * @return Boolean value indicating if error detection code is present
     */
    public boolean getErrorDetectionCode() {

        return m_error_Detection_Code;
    }
    

	/**
	 *
	 * Returns the signing certificate in X509Certificate object
	 *
	 * @return X509Certificate object containing the signing certificate
	 */
	public String getContainerName() {
		return m_containerName;
	}

	/**
	 *
	 * Sets the signing certificate
	 *
	 * @param signingCertificate X509Certificate object containing the signing
	 *                           certificate
	 */
	public void setContainerName(String containerName) {
		m_containerName = containerName;
	}	
	
	
}
