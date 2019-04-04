package gov.gsa.conformancelib.configuration;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
	
	// takes a string with key/value parameters, like
	// CARDHOLDER_FINGERPRINTS_OID:513,CARDHOLDER_FACIAL_IMAGE_OID:1281
	// and returns a dictionary
	public static Map<String,String> MapFromString(String parameters)
	{
		HashMap<String,String> rv = new HashMap<String,String>();
		List<String> parameterList = ParameterUtils.CreateFromString(parameters);
		for(String p : parameterList) {
			if(p.contains(":")) {
				String[] kv = p.split(":");
				if(kv.length == 2) {
					rv.put(kv[0], kv[1]);
				} else {
					s_logger.error("Unexpected format in parameter string {}", parameters );
				}
			}
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
