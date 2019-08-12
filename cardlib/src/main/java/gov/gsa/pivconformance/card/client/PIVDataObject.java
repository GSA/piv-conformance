package gov.gsa.pivconformance.card.client;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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
    protected static HashMap<BerTag, byte[]> m_content;
    // This will be either the embedded cert in the signature, if present, otherwise null
    private X509Certificate m_signerCert;
    // This is always here (via DataModelSingleton) and is the default used by a consumer if m_hasOwnSignerCert is false
    //private X509Certificate m_chuidSignerCert;
    // This will be zero or one, and reflects the number of certs in this object
    private int m_signerCertCount;
    // This will be true *only* when this object has its own cert
    private boolean m_hasOwnSignerCert;
    // Prefetch
    private byte[] m_signedAttrsDigest;
    private byte[] m_computedDigest;
    
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
        m_signerCert = null;
        m_signerCertCount = 0;
        m_hasOwnSignerCert = false;
        m_signedAttrsDigest = null;
        m_computedDigest = null;
    }

    /**
     *
     * Constructor that creates a specific PIV data object based on the passed in OID
     *
     * @param OID String containing OID identifying PIV data object
     */
    public PIVDataObject(String OID) {
        m_OID = OID;
        m_mandatory = APDUConstants.isContainerMandatory(m_OID);
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
    * Returns the number of certs found in this object
    *
    * @return number of certs found in this object
    */
   public int getCertCount() {
       return m_signerCertCount;
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
     * Returns the certificate in this object
     *
     * @return X509Certificate object containing the certificate or null if no cert exists
     */
    public X509Certificate getSignerCert() {
        return m_signerCert;
    }

    /**
     *
     * Sets the certificate embedded in this object
     *
     * @param cert X509Certificate object containing the certificate
     */
    public void setSignerCert(X509Certificate cert) {
        m_signerCert = cert;
        m_signerCertCount++; // TODO: Sneaky; should use a private setter to set this
    }
  
    /**
    *
    * Returns the CHUID signer certificate in this object
    *
    * @return X509Certificate object containing the CHUID signer cert for this card
    */
   public X509Certificate getChuidSignerCert() {
       return DataModelSingleton.getInstance().getChuidSignerCert(); // TODO: Temporary home until refactor
   }

   /**
    *
    * Sets the CHUID signing certificate for this object in the event it doesn't have its own
    * signing cert (which is probably almost always).
    *
    * @param cert X509Certificate object containing the CHUID signing certificate
    */
   public void setChuidSignerCert(X509Certificate cert) {
	   DataModelSingleton.getInstance().setChuidSignerCert(cert); // TODO: Temporary
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
    * Indicates whether this object has an embedded content signer cert 
    *
    */
   
   public boolean hasOwnSignerCert() {
	   return m_signerCertCount > 0;
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
	 * @param tag the tag 
	 * @param valueLen the value, as counted by byte[].length of the value
	 * @return zero if the value meets all length requirements for that tag, < 0 when the
	 * length is less than the low bound, > 0 if the length is greater than the high bound.
	 * For rules that require either of two values, the value returned indicates which of
	 * the two values matched with a 0x10 or 0x01 (low or high).
	 * @throws Exception 
	 */
    public boolean inBounds(String oid) throws Exception {
    	String name = APDUConstants.oidNameMAP.get(oid);
    	if (name == null) {
    		return false;
    	}
    	// Iterate over each tag and corresponding value
    	Iterator<Map.Entry<BerTag, byte[]>> it = m_content.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            BerTag tag = (BerTag) pair.getKey();
            byte value[] = (byte[]) pair.getValue();
            // Check length
            if (!(this.m_lengthOk = this.inBounds (name, tag, value.length))) {
            	return false;
            }
        }
        return true;
    }   
 
    
	/**
	 * Gets the signed attributes message digest extracted from SignerInfo
	 * 
	 * @return bytes in the digest
	 */
    	
	public byte[] getSignedAttrsDigest() {
		return m_signedAttrsDigest;
	}
    
	/**
	 * Sets the message digest in the signed attributes
	 * 
	 * @param the bytes of the digest
	 * 
	 */	
	public void setSignedAttrsDigest(byte[] digest) {
		m_signedAttrsDigest = digest;
    }
	
	/**
	 * Gets the precomputed message digest of the content
	 * 
	 * @return bytes in the digest
	 */
    	
	public byte[] getComputedDigest() {
		return m_computedDigest;
	}
    	
    /**
     * Sets the computed digest of the object
     * 
     * @param the bytes of the digest
     * 
     * @returns the bytes of the digest
     */
    
	public void setComputedDigest(byte[] digest) {
        m_computedDigest = digest;
	}
    
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

    /**
     * Returns boolean value indicating if error detection code had any bytes
     *
     * @return Boolean value indicating if error detection code had any bytes
     */
	
    public boolean getErrorDetectionCodeHasData() {
		return m_error_Detection_Code_Has_Data;
	}
    
    /**
     * Sets a flag indicating that this object has an embedded content signer cert.
     * 
     * @param hasOwnSignerCert boolean value indicating if this object has its own embedded signer cert
     */
    
    public void setHasOwnSignerCert(boolean hasOwnSignerCert) {
		m_hasOwnSignerCert = hasOwnSignerCert;
    }

    /**
     * Returns boolean value indicating if this object has its own embedded signer cert
     *
     * @return Boolean value indicating if this object has its own embedded signer cert
     */
    public boolean getHasOwnSignerCert() {
		return m_hasOwnSignerCert;
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
}
