package gov.gsa.pivconformance.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.Properties;

public class VersionUtils {
    private static final Logger s_logger = LoggerFactory.getLogger(VersionUtils.class);

    static Properties s_properties;

    public static final String PACKAGE_VERSION = "build.version";

    public static final String PACKAGE_REVISION = "git.commit.id";
    public static final String PACKAGE_REVISION_TIME = "git.commit.time";
    public static final String PACKAGE_BUILD_TIME = "build.time";

    static {
        s_properties = new Properties();
        InputStream pis = null;
        try {
            pis = VersionUtils.class.getClassLoader().getResourceAsStream("version.properties");
            s_properties.load(pis);
        } catch(Exception e) {
            s_logger.error("Unable to read version.properties file from classpath", e);
            s_properties.setProperty(PACKAGE_VERSION, "ERROR");
            s_properties.setProperty(PACKAGE_REVISION, "ERROR");
            s_properties.setProperty(PACKAGE_BUILD_TIME, "ERROR");
            s_properties.setProperty(PACKAGE_REVISION_TIME, "ERROR");

        }
        if(!s_properties.containsKey(PACKAGE_VERSION)) {
            s_logger.error("Version.properties was read from classpath but did not contain versioning information");
            s_properties.setProperty(PACKAGE_VERSION, "ERROR");
            s_properties.setProperty(PACKAGE_REVISION, "ERROR");
            s_properties.setProperty(PACKAGE_BUILD_TIME, "ERROR");
            s_properties.setProperty(PACKAGE_REVISION_TIME, "ERROR");
        }

    }

    public static String GetPackageVersionString() {
        return String.format("%s.%s", s_properties.getProperty(PACKAGE_VERSION), s_properties.getProperty(PACKAGE_REVISION));
    }

    public static String GetPackageBuildTime() {
        return s_properties.getProperty(PACKAGE_BUILD_TIME);
    }
}
