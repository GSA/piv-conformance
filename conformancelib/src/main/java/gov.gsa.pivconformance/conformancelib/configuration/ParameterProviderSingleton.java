package gov.gsa.pivconformance.conformancelib.configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ParameterProviderSingleton {
	List< List<String> > m_parameterStack;
	Map<String, List<String>> m_parametersDict;
	Map<String, String> m_containerMap;

    private ParameterProviderSingleton() {
    	reset();
    }
    
    private static final ParameterProviderSingleton INSTANCE = new ParameterProviderSingleton();
    
    public static ParameterProviderSingleton getInstance()
    {
        return INSTANCE;
    }
    
    public void reset() {
    	m_parameterStack = null;
    	m_parameterStack = new ArrayList< List<String> >();
    	m_parametersDict = null;
    	m_parametersDict = new HashMap<String, List<String>>();
    	m_containerMap = null;
    	m_containerMap = new HashMap<String,String>();
    }
    
    public List<String> getNextParameter() {
    	List<String> rv = m_parameterStack.remove(0);
    	return rv;
    }
    
    public void addParameter(List<String> parameter) {
    	m_parameterStack.add(parameter);
    }
    
    public void addNamedParameter(String name, List<String> parameter) {
    	m_parametersDict.put(name, parameter);
    }
    
    public List<String> getNamedParameter(String name) {
    	return m_parametersDict.get(name);
    }
    
    public void addContainer(String test, String oid) {
    	m_containerMap.put(test, oid);
    }
    
    public String getContainer(String test) {
    	return m_containerMap.getOrDefault(test, null);
    }
}
