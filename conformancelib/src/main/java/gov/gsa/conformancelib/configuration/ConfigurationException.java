package gov.gsa.conformancelib.configuration;

public class ConfigurationException extends Exception {
	
	private static final long serialVersionUID = -1495745055942490685L;
	
	public ConfigurationException() { super(); }
	public ConfigurationException(String message) {
		super(message);
	}
	public ConfigurationException(String message, Throwable cause) {
		super(message, cause);
	}

	

}
