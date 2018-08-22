package gov.gsa.pivconformance.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
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
    public static List<String> GetConnectedReaders() {
        ArrayList<String> readerList = new ArrayList<>();
        TerminalFactory tf = TerminalFactory.getDefault();
        List<CardTerminal> terminals = null;
        try {
            s_logger.debug("About to list connected readers");
            terminals = tf.terminals().list();
            s_logger.debug("Done listing connected readers");
        } catch (CardException e) {
            s_logger.error("Failed to list card terminals", e);
            return readerList;
        }
        if(terminals.size() == 0) {
            s_logger.debug("No readers were connected.");
            return readerList;
        }
        int terminalCount = 0;
        for(CardTerminal t : terminals) {
            terminalCount++;
            readerList.add(t.getName());
        }
        s_logger.debug("Found {} readers.", terminalCount);
        return readerList;
    }
}
