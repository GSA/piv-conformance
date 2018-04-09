package gov.gsa.pivconformance.tools;

import gov.gsa.pivconformance.utils.PCSCUtils;
import gov.gsa.pivconformance.utils.VersionUtils;
import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ConformanceTestRunner {
    // slf4j will thunk this through to an appropriately configured logging library
    private static final Logger s_logger = LoggerFactory.getLogger(ConformanceTestRunner.class);
    private static final Options s_options = new Options();
    static {
        s_options.addOption("h", "help", false, "Print this help and exit");
        s_options.addOption( null, "listReaders", false, "Print a list of connected readers and exit");
        // Specify a specific reader, as given by --listReaders. If none is specified the first reader will be used
        s_options.addOption("r", "reader", true, "Use the specified reader for conformance tests");
        s_options.addOption("t", "testConfig", true, "Use the specified test configuration file");
        s_options.addOption(null, "runSelected", true, "Run only the specified test cases (comma separated)");
        s_options.addOption(null, "runTagged", true, "Run all test cases with the specified tags (comma separated)");
        s_options.addOption(null, "dryRun", true, "Collect and configure test cases, and log which ones would be run, but do not execute");
        s_options.addOption("l", "logConfig", true, "Use the specified log configuration file");
        s_options.addOption("o", "outDir", true, "Specify the output directory for reports");
        s_options.addOption("n", false, "Number of times to repeat the run");
    }

    private static void PrintHelpAndExit(int exitCode) {
        new HelpFormatter().printHelp("ConformanceTestRunner <options>", s_options);
        System.exit(exitCode);
    }

    private static List<String> CheckIncompatibleOptions(String option, String incompatibleOptions, CommandLine cmd) {
        List<String> incompatibleOptionList = Arrays.asList(incompatibleOptions.split("\\s*,\\s*"));
        // if the split didn't find anything, just treat the whole string as an option to test
        if(incompatibleOptionList.isEmpty()) {
            incompatibleOptionList.add(incompatibleOptions);
        }
        ArrayList<String> messages = new ArrayList<>();
        for(String opt: incompatibleOptionList) {
            if(cmd.hasOption(opt)) {
                messages.add(option + " cannot be combined with " + opt + ".");
            }
        }
        return messages;
    }

    private static List<String> CheckRequiredOptions(String option, String requiredOptions, CommandLine cmd) {
        List<String> requiredOptionList = Arrays.asList(requiredOptions.split("\\s*,\\s*"));
        // if the split didn't find anything, just treat the whole string as an option to test
        if(requiredOptionList.isEmpty()) {
            requiredOptionList.add(requiredOptions);
        }
        ArrayList<String> messages = new ArrayList<>();
        for(String opt: requiredOptionList) {
            if(!cmd.hasOption(opt)) {
                messages.add(option + " requires that " + opt + " also be specified.");
            }
        }
        return messages;
    }

    private static void LogErrorsIfNonEmptyAndExit(String msg, List<String> messages, int exitCode) {
        if(!messages.isEmpty()) {
            if(msg != null && !msg.isEmpty()) s_logger.error(msg);
            for(String message: messages) {
                s_logger.error(message);
            }
            System.exit(exitCode);
        }
    }

    public static void main(String[] args) {
        s_logger.info("main class: {}", MethodHandles.lookup().lookupClass().getSimpleName());
        s_logger.info("package version: {}", VersionUtils.GetPackageVersionString());
        s_logger.info("build time: {}", VersionUtils.GetPackageBuildTime());

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

        if(cmd.hasOption("listReaders")) {
            List<String> messages = CheckIncompatibleOptions("listReaders", "reader,testConfig,runSingle,runTagged,outDir,n", cmd);
            LogErrorsIfNonEmptyAndExit("Incompatible command line options found", messages, 1);
            List<String> readers = PCSCUtils.GetConnectedReaders();
            if(!readers.isEmpty()) {
                s_logger.info("Currently connected readers:");
                int currReader = 0;
                for (String reader : readers) {
                    currReader++;
                    s_logger.info("{}: {}", currReader, reader);
                }
            } else {
                s_logger.info("No readers are connected.");
            }
            System.exit(0);
        }

        if(cmd.hasOption("testConfig")) {
            List<String> messages = CheckIncompatibleOptions("testConfig", "listReaders", cmd);
            LogErrorsIfNonEmptyAndExit("Incompatible command line options found", messages, 1);
            messages = CheckRequiredOptions("testConfig", "outDir", cmd);
            LogErrorsIfNonEmptyAndExit("Required command line options missing", messages, 1);
        }

    }
}
