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
	private CONSTRAINT m_rule;
	private int m_lowVal;
	private int m_highVal;
	private boolean m_softUpperBound;
	
	// Private constructor
	public TagLengthRule(CONSTRAINT rule, int lowVal, int highVal, boolean softUpperBound) {
		m_rule = rule;
		m_lowVal = lowVal;
		m_highVal = highVal;
		m_softUpperBound = softUpperBound;
	}
	
	// Additional constructor
	public TagLengthRule(CONSTRAINT rule, int lowVal, int highVal) {
		m_rule = rule;
		m_lowVal = lowVal;
		m_highVal = highVal;
		m_softUpperBound = false;
	}
	/**
	 * Eunumeration used to compute lengths of TLV values
	 *
	 */
	public static enum CONSTRAINT {
		FIXED, OR, VARIABLE
	};
	
	/*
	 * Provides the RULE (for lack of a better word at the time) of the rule
	 * 
	 * @return the RULE
	 */
	
	public CONSTRAINT getRule() {
		return m_rule;
	}
	
	/*
	 * Provides the low value in the rule
	 * 
	 * @return the low value in the rule
	 */	
	public int getLowVal() {
		return m_lowVal;
	}
	
	/*
	 * Provides the high value in the rule
	 * 
	 * @return the high value in the rule
	 */
	
	public int getHighVal() {
		return m_highVal;
	}
	
	/*
	 * Indicates if a soft boundary exists (due to an embedded CMS or signing cert)
	 * 
	 * @return whether this value is eligible to have a soft upper bound
	 */
	
	public boolean hasSoftUpperBound() {
		return m_softUpperBound;
	}
}
	