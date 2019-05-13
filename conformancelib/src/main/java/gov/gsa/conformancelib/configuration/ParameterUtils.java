package gov.gsa.conformancelib.configuration;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.tests.ConformanceTestException;

public class ParameterUtils {
	
	private static Logger s_logger = LoggerFactory.getLogger(ParameterUtils.class);

	public static String CreateFromList(List<String> parameters)
	{
		return String.join(",", parameters);
	}
	
	public static List<String> CreateFromString(String parameters, String delimiter)
	{
		List<String> rv;
		String[] arrayParams = parameters.split(delimiter);
		rv = Arrays.asList(arrayParams);
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
	 * X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID:1.2.840.113549.1.1.1|1.2.840.10045.2.1+1.2.840.10045.3.1.7
	 * 
	 * Values themselves can have their own parameters, shown in the following parameter snippet:
	 * 
	 *   {@code X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID:1.2.840.113549.1.1.1|1.2.840.10045.2.1+1.2.840.10045.3.1.7,}.
	 * 
	 * 1. Duplicate OID keys are not allowed
	 * 2. Split the keys:value pairs into a List
	 * 3. We create a Map<String,List<String>>).  If the value has "|" then more than one value is allowed.
	 * 4. Create the inner map by splitting on "|" and adding to the List. A single value is still a one-element List<String>.
	 * 
	 * @param parameters string containing list of comma-separated parameters, themselves possibly with parameters 
	 * @return HashMap of key:value pairs
	 * @throws ConformanceTestException
	 */
	public static Map<String,List<String>> MapFromString(String parameters, String delimiter) {
		HashMap<String,List<String>> rv = new HashMap<String,List<String>>();
		List<String> parameterList = ParameterUtils.CreateFromString(parameters, ",");
		String logMessage = "";
		
		try {	
			if (parameterList.size() == 0) {
				logMessage = "Parameter list expected but none found";
				s_logger.error(logMessage);
				throw new ConformanceTestException(logMessage);
			}
			
			for(String p : parameterList) {
				List<String> value = null;
				if(p.contains(":")) {
					// Type 3, with ":" separating key and value
					System.out.println("Type 3, with \":\" separating key and value\n");
					String[] kv = p.split(":");
					boolean okayToPut = false;
					if(kv.length == 2) {
						// Could be an inner key:value pair, or just a key
						if (kv[1].toLowerCase().compareTo("null") == 0) {
							System.out.println("***************** sub-parameter is null\n");
							okayToPut = value.add(null));
						} else {
							
							okayToPut = value.add(kv[1]);
							System.out.println("***************** sub-parameter is NOT null:" + kv[1] + "\n");
						}
					} else if (kv.length == 1) {
						// Empty string == absent
						System.out.println("****************** sub-parameter is the empty string (absent)\n");
						okayToPut = value.add("");
					} else {
						logMessage = "Unexpected format in parameter string (" +  p + ")";
						s_logger.error(logMessage);
						throw new ConformanceTestException(logMessage);
					}
					
					if (value != null) {
						ListIterator<String> li = value.listIterator();
						while (li.hasNext()) {
							if (li.next().toString().contains("|")) {
								// A list of allowable values - nothing too fancy
								System.out.println("****************** An allowable value of: " + li.toString()  + "\n");
								List subParamList = ParameterUtils.CreateFromString(parameters, "|");
							}
						}
					}
					rv.put(kv[0], value);
				} else {
					// Type 2 with comma separated values - just put them into the map
					// and let the duplicates filter out.
					System.out.println("*Type 2 with comma-separated values\n");
					rv.put(kv[0], ;
				}
			}
		} catch (ConformanceTestException e) {
			s_logger.error(logMessage);
		}
		return rv;		
	}

	public static void main(String[] args) {
		String csvParams1 = "CARDHOLDER_FINGERPRINTS_OID:513,CARDHOLDER_FACIAL_IMAGE_OID:1281";
		String csvParams2 = 
				"X509_CERTIFICATE_FOR_PIV_AUTHENTICATION_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7,\n" + 
				"X509_CERTIFICATE_FOR_CARD_AUTHENTICATION_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7,\n" + 
				"X509_CERTIFICATE_FOR_DIGITAL_CERTIFICATE_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7|1.2.840.10045.2.1+1.3.132.0.34,\n" + 
				"X509_CERTIFICATE_FOR_KEY_MANAGEMENT_OID:1.2.840.113549.1.1.1+NULL|1.2.840.10045.2.1+1.2.840.10045.3.1.7|1.2.840.10045.2.1+1.3.132.0.34";
		Map<String, List<String>> map1 = MapFromString(csvParams1);
		Map<String, List<String>> map2 = MapFromString(csvParams2);
		System.out.println("Done\n");
	}
}
