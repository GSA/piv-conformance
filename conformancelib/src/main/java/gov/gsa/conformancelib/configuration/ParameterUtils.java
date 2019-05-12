package gov.gsa.conformancelib.configuration;

import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
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
	
	public static List<String> CreateFromString(String parameters)
	{
		List<String> rv;
		String[] arrayParams = parameters.split(",");
		rv = Arrays.asList(arrayParams);
		return rv;
	}

	/**
	 * Takes a string with key:value parameters, like CARDHOLDER_FINGERPRINTS_OID:513,CARDHOLDER_FACIAL_IMAGE_OID:1281
	 * and returns a dictionary
	 * @param parameters string containing list of comma-separated key:value pairs 
	 * @return HashMap of key:value pairs
	 * @throws ConformanceTestException
	 */
	public static Map<String,String> MapFromString(String parameters)
	{
		HashMap<String,String> rv = new HashMap<String,String>();
		List<String> parameterList = ParameterUtils.CreateFromString(parameters);
		String logMessage = "";
		
		try {	
			if (parameterList.size() == 0) {
				logMessage = "Parameter list expected but none found";
				s_logger.error(logMessage);
				throw new ConformanceTestException(logMessage);
			}
			
			for(String p : parameterList) {
				if(p.contains(":")) {
					String[] kv = p.split(":");
					if(kv.length == 2) {
						// null, NULL == null
						if (kv[1].toLowerCase().compareTo("null") == 0) {
							kv[1] = null;
						}
						rv.put(kv[0], kv[1]);
					} else if (kv.length == 1) {
						// Empty string == absent
						rv.put(kv[0], "");
					} else {
						logMessage = "Unexpected format in parameter string (" +  p + ")";
						s_logger.error(logMessage);
						throw new ConformanceTestException(logMessage);
					}
				}
			}
		} catch (ConformanceTestException e) {
			s_logger.error(logMessage);
		}
		return rv;
	}
	
	public boolean isNumeric(String valueStr) throws ConformanceTestException
	{
		boolean rv = false;
		String logMessage = "";

		// Only perform this check if there's a value present
		if (valueStr.length() > 0) {
			try {
				int value = Integer.parseInt(valueStr);
				rv = true;
			} catch(NumberFormatException e) {
				logMessage = "Non-numeric value supplied in key:value pair (" + valueStr + ")";
				s_logger.error(logMessage);
				throw new ConformanceTestException(logMessage);
			}
		} else {
			rv = true;
		}
		
		return rv;
	}

	public static void main(String[] args) {
		String csvParams = "CARDHOLDER_FINGERPRINTS_OID:513,CARDHOLDER_FACIAL_IMAGE_OID:1281";
		List<String> listParams;
		String[] arrayParams = csvParams.split(",");
		listParams = Arrays.asList(arrayParams);
		String csvParams2 = String.join(",", listParams);
		System.out.println(csvParams);
		System.out.println(csvParams2);
		int i = 0;
		for(String s : listParams) {
			i++;
			System.out.println(i + ": " + s);
		}
	}
}
