/**
 * 
 */
package gov.gsa.pivconformance.tlv;

/**
 * One of three classes to encapsulate the rather fuzzy max lengths per Tables 8-43 in SP
 * 800-73-4 TODO: Add logic to account for embedded content signing certs in
 * biometrics. 
 */
public class TagLengthRule {
	private RULE m_rule;
	private int m_lowVal;
	private int m_highVal;
	
	// Private constructor
	public TagLengthRule(RULE rule, int lowVal, int highVal) {
		m_rule = rule;
		m_lowVal = lowVal;
		m_highVal = highVal;
	}
	/**
	 * Eunumeration used to compute lengths of TLV values
	 *
	 */
	public static enum RULE {
		FIXED, OR, VARIABLE
	};
	
	public RULE getRule() {
		return m_rule;
	}
	
	public int getLowVal() {
		return m_lowVal;
	}
	
	public int getHighVal() {
		return m_highVal;
	}
}
	