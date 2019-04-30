package gov.gsa.conformancelib.pivconformancetools;

import java.io.Console;
import java.io.File;
import java.net.URL;
import java.util.List;
import java.util.Map;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.utils.PCSCUtils;

public class ContainerDump {
	
	private static final Options s_options = new Options();
    private static final Logger s_logger = LoggerFactory.getLogger(ContainerDump.class);
	
    static {
        s_options.addOption("h", "help", false, "Print this help and exit");
        s_options.addOption("listOids", false, "list container OIDs and exit");
        s_options.addOption("a", "appPin", true, "PIV application PIN");
        s_options.addOption("l", "login", false, "Log in to PIV applet using PIV application PIN prior to attempting dump");
        s_options.addOption("defaultGetResponse", false, "Use default javax.scardio GET RESPONSE processing");
        s_options.addOption("o", "outDir", true, "Directory to receive containers");
        
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("ContainerDump <options>", s_options);
        System.exit(exitCode);
    }

	public static void main(String[] args) {
    	URL location = ContainerDump.class.getProtectionDomain().getCodeSource().getLocation();
		s_logger.info("current binary directory: {}", location.getFile());
        PCSCUtils.ConfigureUserProperties();
        CommandLineParser p = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = p.parse(s_options, args);
        } catch (ParseException e) {
            s_logger.error("Failed to parse command line arguments", e);
            PrintHelpAndExit(1);
        }
        if(cmd.hasOption("help")) {
            PrintHelpAndExit(0);
        }
        if(cmd.hasOption("listOids")) {
        	for(String o : APDUConstants.AllContainers()) {
        		Map<String, String> names = APDUConstants.oidNameMAP;
        		System.out.println(o + ": " + names.get(o));
        	}
        	System.exit(0);
        }
        String appPin = null;
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        if(cmd.hasOption("login")) {
        	if(cmd.hasOption("appPin")) {
        		appPin = cmd.getOptionValue("appPin");
        	} else {
        		Console cons = System.console();
        		char[] passwd;
        		if (cons != null && (passwd = cons.readPassword("[Enter %s]", "PIV Application Pin")) != null) {
        			appPin = new String(passwd);
        			css.setApplicationPin(appPin);
        		}
        	}
        }
        List<String> containers = null;
        if(cmd.getArgList().size() == 0) {
        	containers = APDUConstants.AllContainers();
        } else {
        	containers = cmd.getArgList();
        }
        String outDir = System.getProperty("user.dir");
        if(cmd.hasOption("outDir")) {
        	outDir = cmd.getOptionValue("outDir");
        	File odf = new File(outDir);
        	if(!odf.exists()) {
        		boolean created = false;
        		s_logger.info("Output directory {} does not exist. Attempting to create it", odf.getAbsolutePath());
        		created = odf.mkdirs();
        		if(!created) {
        			s_logger.error("{} was specified as an output directory but didn't exist and couldn't be created.",
        					odf.getAbsolutePath());
        			System.exit(1);
        		}
        	}
        	if(!odf.isDirectory()) {
        		s_logger.error("{} was specified as an output directory but is not a directory", odf.getAbsolutePath());
        		System.exit(1);
        	}
        }
        for(String container: containers) {
        	s_logger.info("dumping container to {}/{}.bin", outDir, container);
        }
	}

}
