/**
 * 
 */
package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;

public class DataModelSingleton {

	TagBoundaryManager m_containerLengthRules;
	
    private DataModelSingleton() {
    	reset();
    }
    
    private static final DataModelSingleton INSTANCE = new DataModelSingleton();
    
    public static DataModelSingleton getInstance() {
        return INSTANCE;
    }
    
    public void reset() {
    	m_containerLengthRules = null;
    	m_containerLengthRules = new TagBoundaryManager();
    }
 
	public void loadLengthRules() {
		if (m_containerLengthRules == null)
			m_containerLengthRules = new TagBoundaryManager();
	}
	
	public TagBoundaryManager getLengthRules() {
		if (m_containerLengthRules == null)
			loadLengthRules();
		
		return m_containerLengthRules;
	}
	
	public void setLengthRules(TagBoundaryManager clf) {
		m_containerLengthRules = clf;
	}
}