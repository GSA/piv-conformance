package gov.gsa.conformancelib.configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.pivconformance.card.client.CardClientException;

public class ParameterUtils {
	
	private static Logger s_logger = LoggerFactory.getLogger(ParameterUtils.class);

	public static String CreateFromList(List<String> parameters)
	{
		return String.join(",", parameters);
	}
	
	public static String[] CreateFromString(String parameters, String delimiter)
	{
		String[] rv = parameters.split(delimiter);
		return rv;
	}

	public static Map<String, List<String>> MapFromString(String parameters)
	{
		return (MapFromString(parameters, ","));
	}
	
	/**
	 * Takes a string in the form of:
	 * 1. value parameters, like 1,2,3 and 
	 * 2. key:value parameters, like CARDHOLDER_FINGERPRINTS_OID:513,CARDHOLDER_FACIAL_IMAGE_OID:1281
	 * and returns a dictionary:
	 * 
	 * String "CARDHOLDER_FINGERPRINTS_OID" => List<String>(513)
	 * 
	 * 3. key:value parameters with values corresponding to the allowable values by separating them with "|" symbols like
	 * X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID:1.2.840.113549.1.1.1|11.2.840.113549.1.1.11
	 * 
	 * Values themselves can have their own parameters, shown in the following parameter snippet:
	 * 
	 *  X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID:1.2.840.113549.1.1.1|1.2.840.10045.2.1+1.2.840.10045.3.1.7,
	 * 
	 * 1. Duplicate OID keys are not allowed
	 * 2. Split the keys:value pairs into a List
	 * 3. We create a Map<String,List<String>>).  If the value has "|" then more than one value is allowed.
	 * 4. Create the inner map by splitting on "|" and adding to the List. A single value is still a one-element List<String>.
	 * 
	 * @param parameters string containing list of comma-separated parameters, themselves possibly with parameters 
	 * @return HashMap of key:value pairs
	 * 
	 * Note that we throw CardClientExceptions here to capture our own issues with the database params
	 */
	public static Map<String,List<String>> MapFromString(String parameters, String delimiter) {
		HashMap<String,List<String>> rv = new HashMap<String,List<String>>();
		String[] parameterList = ParameterUtils.CreateFromString(parameters, delimiter);
		String logMessage = "";
		try {	
			if (parameterList.length == 0) {
				logMessage = "Parameter list expected but none found";
				s_logger.error(logMessage);
				throw new CardClientException(logMessage);
			}
			
			for(String p : parameterList) {
				ArrayList<String> value = new ArrayList<String>();
				if(p.contains(":")) {
					// Type 3, with ":" separating key and value
					String[] kv = p.split(":");

					if(kv.length == 2) {
						// Could be an inner key:value pair, or just a key
						if (kv[1].toLowerCase().compareTo("null") == 0) {
							value.add(null);
						} else {
							value.add(kv[1]);
						}
					} else if (kv.length == 1) {
						// Empty string == absent
						value.add("");
					} else {
						logMessage = "Unexpected format in parameter string (" +  p + ")";
						s_logger.error(logMessage);
						throw new CardClientException(logMessage);
					}
					// Print out for debugging
					if (value != null) {
						Iterator<String> li = value.iterator();
						while (li.hasNext()) {
							String listItem = li.next();
							if (listItem.contains("|")) {
								// This should have been handled in the atom
								logMessage = "Unhandled pipe-separated sub-parameters";
								throw new CardClientException(logMessage);
							}
						}
					}
					// in this case, p is no longer the key; it's the first element of the kv pair we just split
					rv.put(kv[0], value);
				} else {
					// Type 2 with comma-separated values.  Put them into the map with a null List.
					rv.putIfAbsent(p, null);
				}
			}
			if (rv.isEmpty()) {
				logMessage = "Return HashMap<String, List<String>> is empty";
				s_logger.error(logMessage);
				throw new CardClientException(logMessage);
			}
		} catch (CardClientException e) {
			s_logger.error(logMessage);
		} 
		return rv;		
	}
}
