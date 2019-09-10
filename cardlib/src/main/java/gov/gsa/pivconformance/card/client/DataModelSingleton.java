/**
 * 
 */
package gov.gsa.pivconformance.card.client;

import java.security.cert.X509Certificate;

import gov.gsa.pivconformance.tlv.*;

/**
 * This class is used indirectly by the test atoms.  It instantiates some
 * known SP 800-73 rules. Initially being used to manage the container lengths
 * in Tables 8-43.
 * 
 */

public class DataModelSingleton {

	TagBoundaryManager m_tagLengthRules;
    X509Certificate m_chuidSignerCert;
	
    private DataModelSingleton() {
    	reset();
    }
    
    /*
     * The INSTANCE
     */
    
    private static final DataModelSingleton INSTANCE = new DataModelSingleton();
    
    /**
     * Public accessor of this so it can be instantiated by the framework
     * 
     * @return
     */
    
    public static DataModelSingleton getInstance() {
        return INSTANCE;
    }
    
    /**
     * Reset
     */
    
    public void reset() {
    	m_tagLengthRules = null;
    	m_tagLengthRules = new TagBoundaryManager();
    	m_chuidSignerCert = null;
    }
    
    /**
     * Initialize
     */
 
	public void loadLengthRules() {
		if (m_tagLengthRules == null)
			m_tagLengthRules = new TagBoundaryManager();
	}
	
	/**
	 * Day-to-day public accessor
	 * 
	 * @return the SP 800-73-* tag length rules
	 */
	
	public TagBoundaryManager getLengthRules() {
		if (m_tagLengthRules == null)
			loadLengthRules();
		
		return m_tagLengthRules;
	}
	
	/**
	 * Setter
	 * 
	 * @param clf
	 */
	
	public void setLengthRules(TagBoundaryManager clf) {
		m_tagLengthRules = clf;
	}
	
	/**
	 * Gets the cached CHUID signer cert
	 * 
	 * @return the cached CHUID signer cert
	 */
	
	public X509Certificate getChuidSignerCert() {
		return m_chuidSignerCert;
	}
	
	/**
	 * Sets the cached CHUID signer cert
	 * @param cert
	 */
	
	public void setChuidSignerCert(X509Certificate cert) {
		if (m_chuidSignerCert == null && cert != null) // Set once and protect
			m_chuidSignerCert = cert;
	}
}