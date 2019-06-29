package gov.gsa.conformancelib.pivconformancetools;

import java.io.Console;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.CardInfoController;
import gov.gsa.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.conformancelib.tests.ConformanceTestException;
import gov.gsa.conformancelib.utilities.CardUtils;
import gov.gsa.pivconformance.card.client.APDUConstants;
import gov.gsa.pivconformance.card.client.AbstractPIVApplication;
import gov.gsa.pivconformance.card.client.MiddlewareStatus;
import gov.gsa.pivconformance.card.client.PIVDataObject;
import gov.gsa.pivconformance.card.client.PIVDataObjectFactory;
import gov.gsa.pivconformance.card.client.X509CertificateDataObject;
import gov.gsa.pivconformance.utils.PCSCUtils;

public class ContainerDump {
	
	private static final Options s_options = new Options();
    private static final Logger s_logger = LoggerFactory.getLogger(ContainerDump.class);
	
    static {
        s_options.addOption("h", "help", false, "Print this help and exit");
        s_options.addOption("listOids", false, "list container OIDs and exit");
        s_options.addOption("listReaders", false, "list connected readers and exit");
        s_options.addOption("a", "appPin", true, "PIV application PIN");
        s_options.addOption("l", "login", false, "Log in to PIV applet using PIV application PIN prior to attempting dump");
        s_options.addOption("defaultGetResponse", false, "Use default javax.scardio GET RESPONSE processing");
        s_options.addOption("o", "outDir", true, "Directory to receive containers");
        s_options.addOption("reader", true, "Use the specified reader instead of the first one with a card");
        s_options.addOption("", "parseFile", true, "Decode a container stored in a file");
        
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("ContainerDump <options>", s_options);
        System.exit(exitCode);
    }

	public static void main(String[] args) {
    	URL location = ContainerDump.class.getProtectionDomain().getCodeSource().getLocation();
		s_logger.info("current binary directory: {}", location.getFile());
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
        if(cmd.hasOption("parseFile")) {
        	String file = cmd.getOptionValue("parseFile");
			Path filePath = Paths.get(file);
			String[] argv = cmd.getArgs();
			if(argv.length != 1) {
				System.err.println("parseFile requires a single containerOID to be specified");
			}
			String fileOid = argv[0];
			byte[] fileData = null;
			try {
				fileData = Files.readAllBytes(filePath);
			} catch (IOException e) {
				s_logger.error("Unable to read from file {}", file, e);
				System.exit(1);
			}
			PIVDataObject o = PIVDataObjectFactory.createDataObjectForOid(fileOid);

			o.setOID(fileOid);
			o.setBytes(fileData);
			boolean decoded = o.decode();
			if(!decoded) {
				s_logger.error("Unable to decode container from dump");
				System.exit(1);
			} else {
				s_logger.info("Successfully decoded {} as {}", file, fileOid);
			}
			System.exit(0);
        }
        if(!cmd.hasOption("defaultGetResponse")) {
        	s_logger.info("Using cardlib GET RESPONSE instead of java default");
			System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
			System.setProperty("sun.security.smartcardio.t1GetResponse", "false");
        } else {
        	s_logger.info("Using java's default GET RESPONSE handling");
        }
        PCSCUtils.ConfigureUserProperties();
        if(cmd.hasOption("listReaders")) {
        	List<CardTerminal> readers = new ArrayList<CardTerminal>();
        	List<String> readerNames = PCSCUtils.GetConnectedReaders();
        	if(readerNames.size() == 0) {
        		s_logger.error("No readers were connected");
        		System.exit(1);
        	}
        	for(String readerName : readerNames) {
        		readers.add(PCSCUtils.TerminalForReaderName(readerName));
        	}
        	int readerNum = 0;
        	for(CardTerminal reader : readers) {
        		readerNum++;
        		boolean cardInserted = false;
				try {
					cardInserted = reader.isCardPresent();
				} catch (CardException e) {
					s_logger.error("Caught exception querying {}", reader.getName(), e);
				}
        		System.out.println("[" + readerNum + "]: " + reader.getName() + " (" + (cardInserted ? "card present":"card not present") + ")" );
        	}
        	System.out.println(readerNum + " readers connected.");
        }
        String appPin = null;
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        if(cmd.hasOption("reader")) {
        	String readerName = cmd.getOptionValue("reader");
        	CardTerminal reader = PCSCUtils.TerminalForReaderName(readerName);
        	css.setTerminal(reader);
        } else {
        	String readerName = PCSCUtils.GetFirstReaderWithCardPresent();
        	if(readerName == null) {
        		s_logger.error("No connected reader contains a smart card. Insert a card and retry.");
        		System.exit(1);
        	}
        	s_logger.info("Using card in {}", readerName);
        	CardTerminal reader = PCSCUtils.TerminalForReaderName(readerName);
        	css.setTerminal(reader);
        }
        try {
			CardUtils.setUpPivAppHandleInSingleton();
		} catch (ConformanceTestException e) {
			s_logger.error("Failed to set up PIV applet connection.", e);
			System.exit(1);
		}
        if(cmd.hasOption("login")) {
        	if(cmd.hasOption("appPin")) {
        		appPin = cmd.getOptionValue("appPin");
        		css.setApplicationPin(appPin);
        	} else {
        		Console cons = System.console();
        		char[] passwd;
        		if (cons != null && (passwd = cons.readPassword("[Enter %s]", "PIV Application Pin")) != null) {
        			appPin = new String(passwd);
        			css.setApplicationPin(appPin);
        		}
        	}
        	try {
        		int retries = CardInfoController.getAppPinRetries();
        		if(retries < 2) {
        			s_logger.error("Fewer than two PIN retries remain. Cowardly refusing to test card.");
        			System.exit(1);
        		}
				CardUtils.authenticateInSingleton(false);
			} catch (ConformanceTestException e) {
				s_logger.error("Failed to authenticate to card.", e);
				System.exit(1);
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
        	AbstractPIVApplication piv = css.getPivHandle();
        	if(piv == null) {
        		s_logger.error("Invalid PIV handle in card settings singleton. Aborting.");
        		System.exit(1);
        	}
        	PIVDataObject obj = PIVDataObjectFactory.createDataObjectForOid(container);
        	if(obj == null) {
        		s_logger.error("Unable to instantiate PIV data object for {}", container);
        		continue;
        	}
        	MiddlewareStatus result = piv.pivGetData(css.getCardHandle(), container, obj);
        	if(result != MiddlewareStatus.PIV_OK) {
        		s_logger.error("pivGetData() returned {} for container {}", result, container);
        		continue;
        	}
        	FileOutputStream outFile;
			try {
				outFile = new FileOutputStream(new File(outDir + "/" + container + ".bin"));
			} catch (FileNotFoundException e) {
				s_logger.error("Unable to create file for writing", e);
				continue;
			}
        	try {
				outFile.write(obj.getBytes());
				outFile.close();
			} catch (IOException e) {
				s_logger.error("Caught exception while writing data for container {} to file", container, e);
			}
        	s_logger.info("Finished dumping {}", container);
        }
	}

}
