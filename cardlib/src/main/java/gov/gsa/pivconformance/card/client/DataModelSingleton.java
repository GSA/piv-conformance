/**
 * 
 */
package gov.gsa.pivconformance.card.client;

import gov.gsa.pivconformance.tlv.*;

public class DataModelSingleton {

	TagLengthFactory m_containerLengthRules;
	
    private DataModelSingleton() {
    	reset();
    }
    
    private static final DataModelSingleton INSTANCE = new DataModelSingleton();
    
    public static DataModelSingleton getInstance() {
        return INSTANCE;
    }
    
    public void reset() {
    	m_containerLengthRules = null;
    	m_containerLengthRules = new TagLengthFactory();
    }
 
	public void loadLengthRules() {
		if (m_containerLengthRules == null)
			m_containerLengthRules = new TagLengthFactory();
	}
	
	public TagLengthFactory getLengthRules() {
		if (m_containerLengthRules == null)
			loadLengthRules();
		
		return m_containerLengthRules;
	}
	
	public void setLengthRules(TagLengthFactory clf) {
		m_containerLengthRules = clf;
	}
}