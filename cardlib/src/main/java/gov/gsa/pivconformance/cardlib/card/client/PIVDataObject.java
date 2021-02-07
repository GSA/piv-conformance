package gov.gsa.pivconformance.cardlib.card.client;

import java.util.*;
import java.util.Map.Entry;

import gov.gsa.pivconformance.cardlib.tlv.*;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a PIV data object as read to or written from the card. Subclasses
 * may provide abstractions for field access.
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
	private final TagBoundaryManager m_tagLengthRules = DataModelSingleton.getInstance().getLengthRules();
	private boolean m_lengthOk;
	// TODO: Cache these tags
	protected HashMap<BerTag, byte[]> m_content;
	private String m_name;
	private static final List<String> m_oidList = new ArrayList<String>();
	private String m_containerName;
	private ArtifactWriter m_artifactCache;

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
		m_artifactCache = new ArtifactWriter("piv-artifacts");
	}

	/**
	 *
	 * Constructor that creates a specific PIV data object based on the passed in
	 * OID
	 *
	 * @param OID String containing OID identifying PIV data object
	 */
	public PIVDataObject(String OID) {
		setOID(OID);
		setMandatory(APDUConstants.isContainerMandatory(m_OID));
		setContainerName(APDUConstants.containerOidToNameMap.get(m_OID));
		setArtifactCache(new ArtifactWriter("piv-artifacts"));
	}

	private void setArtifactCache(ArtifactWriter artifactCache) {
		m_artifactCache = artifactCache;
	}
	
	private ArtifactWriter getArtifactCache() {
		return m_artifactCache;
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
	public byte[] getBytes() {
		return m_dataBytes;
	}

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
	 * Returns friendly name of PIV data object
	 *
	 * @return String containing the friendly name of PIV data object
	 */
	public String getFriendlyName() {
		return APDUConstants.oidNameMap.getOrDefault(m_OID, "Undefined");
	}

	/**
	 * Indicates whether the object associated with the subclass is mandatory.
	 */

	public boolean isMandatory(String oid) {
		return m_mandatory;
	}

	/**
	 * Indicates whether the object associated with the subclass is mandatory.
	 */

	public void setMandatory(boolean flag) {
		m_mandatory = flag;
	}

	/**
	 * Indicates whether the object associated with the subclass is requires a pin.
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
		byte[] rv = APDUConstants.oidMAP.getOrDefault(m_OID, new byte[] {});
		return rv;
	}

	/**
	 * Indicates whether the given length is within boundaries of the rule
	 * 
	 * @param tag      the tag
	 * @param valueLen the value, as counted by byte[].length
	 * @return true if the value meets all length requirements for that tag
	 * @throws Exception
	 */

	private boolean inBounds(String oid, BerTag tag, int valueLen) throws Exception {
		try {
			int diff = m_tagLengthRules.lengthDelta(oid, tag, valueLen);
			if (diff != 0) {
				String tagString = HexUtil.toHexString(tag.bytes);
				String errStr = (String.format("Tag %s length was %d bytes, differs from 800-73 spec by %d", tagString,
						valueLen, diff));
				Exception e = new TagBoundaryException(errStr);
				throw (e);
			}
		} catch (CardClientException e) {
			return false;
		}

		return true;
	}

	public boolean inBounds(String oid) throws Exception {
		// Iterate over each tag and corresponding value
		Iterator<Map.Entry<BerTag, byte[]>> it = m_content.entrySet().iterator();
		while (it.hasNext()) {
			Entry<BerTag, byte[]> pair = it.next();
			BerTag tag = pair.getKey();
			byte[] value = pair.getValue();
			// Check length
			if (!(this.m_lengthOk = this.inBounds(oid, tag, value.length))) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns a list of all of the expected mandatory and optional tags for this object
	 * 
	 * @return a list of BerTags per SP 800-73-4 Appendix A for this object.
	 */
	public List<BerTag> expectedTagList() {
		List<BerTag> expectedTagList = new ArrayList<BerTag>();
		ContainerRuleset ruleSet = m_tagLengthRules.getMaxLenMap(m_OID);
		HashMap<BerTag, TagLengthRule> ruleMap = ruleSet.getTagRuleset();
		Set expectedTagSet =  ruleMap.keySet();
		expectedTagList.addAll(expectedTagSet);
		return expectedTagList;
	}

	/**
	 * Compares the order of the tags received with the order specified in SP 800-73-4 Appendix A.
	 * @return true if the order is correct and false otherwise.
	 */

	public boolean isOrderCorrect() {
		boolean rv = true;
		//If organizational affiliation tag is present check the order
		ArrayList<BerTag> expectTagList = new ArrayList<BerTag>();
		expectTagList.addAll(expectedTagList());
		ArrayList<BerTag> gotTagList = new ArrayList<BerTag>();
		gotTagList.addAll(getTagList());
		int lastIndex = -1;
		for (BerTag outer : gotTagList) {
			int thisIndex = expectTagList.indexOf(outer);
			if(thisIndex < lastIndex) {
				s_logger.error("Tag is out of order: " + outer.toString());
				rv = false;
			}
			lastIndex = thisIndex;
		}
		return rv;
	}
	/**
	 * Dumps the raw container into a file and logs the ascii hex representation of the tags to a file
	 * @param clazz the name of the class dumping the container
	 */
	public void dump(Class<?> clazz) {
		if (!m_oidList.contains(m_OID)) {
			// Get the container name
			String fqContainerName = this.getContainerName();
			String alternateName = APDUConstants.getFileNameForOid(m_OID);
			if (alternateName.compareTo(fqContainerName) != 0)// Failsafe
				s_logger.error("Container names: " + alternateName + " and " + fqContainerName + " are not the same");
			m_artifactCache.saveObject("piv-artifacts", this.getContainerName() + ".dat", m_dataBytes);

			Logger s_containerLogger = LoggerFactory.getLogger(fqContainerName);
			s_containerLogger.debug("Container: {}", fqContainerName);
			s_containerLogger.debug("Raw bytes: {}", Hex.encodeHexString(m_dataBytes));

			List<BerTag> expectedTags = expectedTagList();
			StringBuffer sb = new StringBuffer("Expected tags: Expected tags per SP 800-73-4 Appendix A: ");
			boolean firstTag = true;
			for (BerTag et : expectedTags) {
				if (!firstTag) sb.append(", ");
				boolean firstByte = true;
				for (byte b : et.bytes) {
					if (firstTag) sb.append ("{ ");
					if (firstByte) sb.append("{ "); else sb.append(", ");
					sb.append(String.format("%02X", b & 0xff));
					firstByte = false;
				}
				sb.append(" }");
				firstTag = false;
			}
			sb.append(" }");
			s_logger.debug(sb.toString());

			for (int i = 0; i < m_tagList.size(); i++) {
				BerTag tag = m_tagList.get(i);
				if (tag != null) {
					if (Arrays.equals(TagConstants.CERTIFICATE_TAG, tag.bytes)) {
						s_containerLogger.debug("Certificate tag");
					}
					if (m_content.get(tag) == null) {
						s_containerLogger.warn("Tag[{}] ({}) is null", i, Hex.encodeHexString(tag.bytes));
					} else {
						s_containerLogger.debug("Tag {}: {}", Hex.encodeHexString(tag.bytes),
								Hex.encodeHexString(m_content.get(tag)));
					}
				} else {
					s_containerLogger.warn("Tag[{}] is null", i);
				}
			}
			m_oidList.add(m_OID);
		}
		//setContainerName(null);
	}

	/**
	 * Gets the precomputed message digest of the content
	 * 
	 * @return bytes in the digest
	 */

	/**
	 *
	 * Place holder that will throw RuntimeError if the is a missing implementations
	 * of decode
	 *
	 * @return false
	 */
	public boolean decode() {
		// XXX *** make this throw a RuntimeError once implementations are notionally in
		// place
		s_logger.error("decode() called without a concrete implementation.");
		return false;
	}

	/**
	 *
	 * Returns the length of all containers was found to be okay, false otherwise
	 *
	 * @return True if the length of all containers was found to be okay, false
	 *         otherwise
	 */
	public boolean lengthOk() {
		return m_lengthOk;
	}

	/**
	 *
	 * Returns a String containing hex representation of the raw value of the PIV
	 * data object
	 *
	 * @return String containing hex representation of the raw value of the PIV data
	 *         object
	 */
	public String toRawHexString() {
		return Hex.encodeHexString(m_dataBytes);
	}

	/**
	 *
	 * Returns a String containing PIV data object OID, friendly name and hex
	 * representation of the raw value of the PIV data object
	 *
	 * @return String containing PIV data object OID, friendly name and hex
	 *         representation of the raw value of the PIV data object
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
	 * Sets a boolean value ind icating if the PIV data object is signed
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
	 * Sets the container name for this PIVDataObject
	 *
	 * @param containerName name of this container
	 */
	public void setContainerName(String containerName) {
		m_containerName = containerName;
	}
}