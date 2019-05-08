package gov.gsa.pivconformance.card.client;

import java.lang.reflect.Field;

public class TestFieldResolution {

	public static void main(String[] args) {
		String oidName = "CARDHOLDER_FINGERPRINTS_OID";
		Field oidField = null;
		try {
			oidField = APDUConstants.class.getField(oidName);
			String oid = (String) oidField.get(APDUConstants.class);
			System.out.println(oidName + "=" + oid);

		} catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException e1) {
			e1.printStackTrace();
		}

	}

}
