package gov.gsa.pivconformance.gui;

import gov.gsa.pivconformance.cardlib.card.client.CardHandle;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReaderAndVersionRegressionTest {
    /** Run against the shipped JAR with its bundled runtime, not the build JDK. */
    public static void main(String[] args) throws Exception {
        Path application = Path.of(args[0]).toAbsolutePath().normalize();
        System.setProperty("cct.packaged", "true");
        System.setProperty("cct.data.dir", args[1]);
        CctApplicationPaths.initialize();
        assertEquals(application, CctApplicationPaths.resourceDirectory());
        assertTrue(Files.isRegularFile(CctApplicationPaths.dataDirectory().resolve("x509-certs/cacerts.jks")));
        assertNotNull(java.security.Security.getProvider("SunEC"));
        java.security.Signature.getInstance("RSASSA-PSS");
        java.security.Signature.getInstance("SHA384withECDSA");
        javax.smartcardio.TerminalFactory.getDefault();
        for (String profile : new String[]{"PIV_Production_Cards", "PIV_ICAM_Test_Cards",
                "PIV-I_Production_Cards", "PIV-I_ICAM_Test_Cards"}) {
            String uri = application.resolve(profile + ".db").toUri().toString();
            try (var connection = java.sql.DriverManager.getConnection("jdbc:sqlite:" + uri + "?mode=ro");
                 var statement = connection.createStatement();
                 var rows = statement.executeQuery("SELECT COUNT(*) FROM TestCases")) {
                assertTrue(rows.next());
                assertEquals(489, rows.getInt(1), profile);
            }
        }
        var listener = new org.junit.platform.launcher.listeners.SummaryGeneratingListener();
        var request = org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder.request()
                .selectors(org.junit.platform.engine.discovery.DiscoverySelectors.selectClass(
                        "gov.gsa.pivconformance.conformancelib.tests.ExistingCctRegressionTest")).build();
        org.junit.platform.launcher.core.LauncherFactory.create().execute(request, listener);
        var summary = listener.getSummary();
        summary.printTo(new java.io.PrintWriter(System.out, true));
        summary.printFailuresTo(new java.io.PrintWriter(System.out, true));
        assertEquals(334, summary.getTestsSucceededCount());
        assertEquals(0, summary.getTestsFailedCount());
        assertEquals(0, summary.getTestsSkippedCount());
        System.out.println("Packaged application: resources, four databases, cryptography and 334 regressions passed.");
    }

    @Test
    void packagedLoggingConfigurationStartsAndWritesResultRows(@TempDir Path directory) throws Exception {
        var context = new ch.qos.logback.classic.LoggerContext();
        context.setMDCAdapter(new ch.qos.logback.classic.util.LogbackMDCAdapter());
        context.putProperty("LOG_DIR", directory.toString());
        try {
            var configurator = new ch.qos.logback.classic.joran.JoranConfigurator();
            configurator.setContext(context);
            configurator.doConfigure(Path.of(System.getProperty("cct.repository"),
                    "cardlib/src/main/resources/user_log_config.xml").toFile());
            var problems = context.getStatusManager().getCopyOfStatusList().stream()
                    .filter(status -> status.getLevel() >= ch.qos.logback.core.status.Status.WARN).toList();
            assertTrue(problems.isEmpty(), problems.toString());
            context.getLogger("gov.gsa.pivconformance.conformancelib.testResult")
                    .info("8.1.8,\"Synthetic logging compatibility\",Pass,Pass");
            assertTrue(Files.readString(directory.resolve("conformancelog/conformance_results.csv"))
                    .contains(",8.1.8,\"Synthetic logging compatibility\",Pass,Pass"));
        } finally {
            context.stop();
        }
    }

    @Test
    void changingReaderReleasesTheOldConnection() {
        CardSettingsSingleton settings = CardSettingsSingleton.getInstance();
        settings.reset();
        AtomicInteger disconnects = new AtomicInteger();
        Card previous = new Card() {
            @Override public ATR getATR() { return null; }
            @Override public String getProtocol() { return "T=1"; }
            @Override public CardChannel getBasicChannel() { return null; }
            @Override public CardChannel openLogicalChannel() throws CardException { return null; }
            @Override public void beginExclusive() throws CardException { }
            @Override public void endExclusive() throws CardException { }
            @Override public byte[] transmitControlCommand(int controlCode, byte[] command) throws CardException { return null; }
            @Override public void disconnect(boolean reset) { disconnects.incrementAndGet(); }
        };
        CardHandle handle = new CardHandle();
        handle.setCard(previous);
        handle.setValid(true);
        settings.setCardHandle(handle);
        settings.setReaderIndex(1);

        SimpleTestExecutionPanel.resetCardSession(settings);

        assertEquals(1, disconnects.get());
        assertNull(settings.getCardHandle());
        assertEquals(-1, settings.getReaderIndex());
    }

    @Test
    void versionComesFromBundledResourceDespiteStaleLocalFile(@TempDir Path directory) throws Exception {
        Files.writeString(directory.resolve("build.version"), "1.0.7\n");
        String bundledVersion;
        try (InputStream resource = GuiRunnerApplication.class.getResourceAsStream("/build.version")) {
            bundledVersion = new String(resource.readAllBytes()).trim();
        }
        String previousDirectory = System.getProperty("user.dir");
        try {
            System.setProperty("user.dir", directory.toString());
            assertEquals(bundledVersion, GuiRunnerApplication.getVersion("build.version"));
        } finally {
            System.setProperty("user.dir", previousDirectory);
        }
    }
}
