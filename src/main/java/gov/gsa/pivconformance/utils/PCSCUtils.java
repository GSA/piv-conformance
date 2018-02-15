package gov.gsa.pivconformance.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class PCSCUtils {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(PCSCUtils.class);
    public static void ConfigureUserProperties() {
        String homeDirectoryEnv = System.getenv("HOME");
        if(homeDirectoryEnv == null) {
            return;
        }
        File homeDirectory = new File(homeDirectoryEnv);
        if(!homeDirectory.exists()) return;
        File configFile = new File(homeDirectory, ".pivconformance-pcsc.properties");
        if(configFile.exists()) {
            ConfigureUserProperties(configFile);
        }
    }
    public static void ConfigureUserProperties(File fileName) {
        Properties props = new Properties();
        try {
            props.load(new FileInputStream(fileName));
            props.forEach((key, value) -> {
                s_logger.info("Adding property: '{}' = '{}'", key, value);
                System.setProperty((String)key, (String) value);
            });
        } catch (IOException e) {
            s_logger.error("Unable to read " + fileName.getAbsolutePath(), e);
            return;
        }
    }
}
