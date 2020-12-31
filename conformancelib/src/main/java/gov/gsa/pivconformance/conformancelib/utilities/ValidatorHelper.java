package gov.gsa.pivconformance.conformancelib.utilities;

import gov.gsa.pivconformance.conformancelib.tests.ConformanceTestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;

public class ValidatorHelper {
    private static Logger s_logger = LoggerFactory.getLogger(ValidatorHelper.class);
    public enum PolicyOID {
        ID_FPKI_CERTPCY_PIVI_HARDWARE("2.16.840.1.101.3.2.1.3.18"),
        ID_FPKI_COMMON_HARDWARE("2.16.840.1.101.3.2.1.3.7"),
        ID_FPKI_COMMON_POLICY("2.16.840.1.101.3.2.1.3.6"),
        ID_FPKI_CERTPCY_BASICASSURANCE("2.16.840.1.101.3.2.1.3.2"),
        TEST_ID_FPKI_COMMON_CARDAUTH("2.16.840.1.101.3.2.1.48.13"),
        TEST_ID_FPKI_COMMON_AUTHENTICATION("2.16.840.1.101.3.2.1.48.11"),
        TEST_ID_FPKI_COMMON_HARDWARE("2.16.840.1.101.3.2.1.48.9"),
        TEST_ID_FPKI_CERTPCY_MEDIUMHARDWARE("2.16.840.1.101.3.2.1.48.4");

        private final String value;

        PolicyOID(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Gets a file from the specified resource for the specified class.
     *
     * @param clazz    the class requesting its resource
     * @param fileName the basename of the resource file
     * @return InputStream to the open resource or null if an en exception thrown
     * @throws ConformanceTestException if any error occurs
     */
    public static InputStream getFileFromResourceAsStream(Class clazz, String fileName) throws ConformanceTestException {
        if (clazz != null) {
            s_logger.debug("user.dir and fileName: " + System.getProperty("user.dir") + File.separator + fileName);
        }
        InputStream inputStream = null;
        String msg = null;
        ClassLoader classLoader = clazz.getClassLoader();
        if (classLoader != null) {
            try {
                inputStream = classLoader.getResourceAsStream(fileName);
            } catch (Exception e) {
                msg = "Exception [" + e.getMessage() + "] while accessing " + fileName;
                s_logger.error(msg);
                throw new ConformanceTestException(msg);
            }
        } else {
            msg = "Class parameter was null";
            s_logger.error(msg);
            throw new ConformanceTestException(msg);
        }
        return inputStream;
    }}
