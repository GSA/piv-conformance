package gov.gsa.pivconformance.gui;

import gov.gsa.pivconformance.cardlib.card.client.*;
import gov.gsa.pivconformance.conformancelib.configuration.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.TestIdentifier;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.swing.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.ZipFile;

import static org.junit.jupiter.api.Assertions.*;

class NativeResultsTest {
    @TempDir Path temporary;

    /** Uses the shipped database row, argument source, acquisition path and original CCC decoder. */
    @ParameterizedTest @ValueSource(strings = {"plain", "E3", "B4"})
    void originalCccRouteRecordsCauseReferenceAndPortablePackage(String kind) throws Exception {
        Path root = Path.of(System.getProperty("cct.repository"));
        Path database = root.resolve("conformancelib/testdata/PIV_Production_Cards.db");
        Path golden = root.resolve("cardlib/src/test/resources/gov/gsa/pivconformance/cardlib/test/"
                + "gsa-icam-card-builder/cards/ICAM_Card_Objects/01_Golden_PIV/7 - CCC");
        byte[] ccc = Files.readAllBytes(golden);
        byte[] body = Arrays.copyOf(ccc, ccc.length - 2);
        if (!kind.equals("plain")) body = join(body, APDUUtils.getTLV(new byte[]{(byte) Integer.parseInt(kind, 16)}, new byte[48]));
        byte[] raw = APDUUtils.getTLV(APDUConstants.DATA, join(body, new byte[]{(byte) 0xfe, 0}));
        try (var connection = DriverManager.getConnection("jdbc:sqlite:file:" + database + "?mode=ro")) {
            ConformanceTestDatabase db = new ConformanceTestDatabase(connection);
            TestCaseModel row = new TestCaseModel(db);
            row.retrieveForId(11);
            TestStepModel step = row.getSteps().get(0);
            assertEquals("sp800_73_5_Test_4", step.getTestMethodName());
            var method = Arrays.stream(Class.forName(step.getTestClassName()).getDeclaredMethods())
                    .filter(m -> m.getName().equals(step.getTestMethodName())).findFirst().orElseThrow();
            String selector = step.getTestClassName() + "#" + method.getName() + "("
                    + Arrays.stream(method.getParameterTypes()).map(Class::getName).collect(Collectors.joining(", ")) + ")";
            CardSettingsSingleton card = CardSettingsSingleton.getInstance();
            ParameterProviderSingleton parameters = ParameterProviderSingleton.getInstance();
            card.reset(); parameters.reset();
            card.setTerminal(new CardTerminal() {
                public String getName() { return "Simulated acquisition; no physical card"; }
                public Card connect(String protocol) { throw new AssertionError("Physical card access forbidden"); }
                public boolean isCardPresent() { return true; }
                public boolean waitForCardPresent(long timeout) { throw new AssertionError("Physical card access forbidden"); }
                public boolean waitForCardAbsent(long timeout) { throw new AssertionError("Physical card access forbidden"); }
            });
            card.setCardHandle(new CardHandle());
            card.setLastLoginStatus(CardSettingsSingleton.LOGIN_STATUS.LOGIN_SUCCESS);
            card.setPivHandle(new DefaultPIVApplication() {
                @Override public MiddlewareStatus pivGetData(CardHandle handle, String oid, PIVDataObject object) {
                    assertEquals(APDUConstants.CARD_CAPABILITY_CONTAINER_OID, oid);
                    object.setOID(oid);
                    object.setContainerName(APDUConstants.getFileNameForOid(oid));
                    object.setBytes(raw.clone());
                    return MiddlewareStatus.PIV_OK;
                }
            });
            parameters.addContainer(selector, row.getContainer());
            parameters.addNamedParameter(selector, step.getParameters());
            GuiTestListener listener = new GuiTestListener(false);
            try {
                // Run setup then the main pass: only the latter produces a logical result.
                listener.configureCase(row, false);
                execute(selector, listener);
                assertEquals(0, listener.completedCases().size());
                listener.configureCase(row, true);
                execute(selector, listener);
                assertEquals(1, listener.completedCases().size());
                RunResults.CaseResult result = listener.completedCases().get(0);
                assertEquals(kind.equals("plain") ? TestStatus.PASS : TestStatus.FAIL, result.status());
                assertEquals(1, result.steps().size(), "JUnit containers must not duplicate the invocation");
                RunResults.StepResult recorded = result.steps().get(0);
                assertEquals(1, recorded.references().size());
                assertTrue(recorded.references().get(0).location().contains("Table 9"));
                if (!kind.equals("plain")) {
                    assertTrue(recorded.reason().contains("eliminated tag " + kind));
                    assertFalse(recorded.executionError(), "The intended assertion, not setup/decoding, must fail");
                }
                RunResults snapshot = new RunResults("test", database, Instant.EPOCH, Instant.EPOCH.plusSeconds(2), true, listener.completedCases());
                assertEquals(kind.equals("plain") ? 1 : 0, snapshot.passed());
                assertEquals(kind.equals("plain") ? 0 : 1, snapshot.failed());
                String prefix = "synthetic-run";
                Path csv = temporary.resolve("logs/conformancelog/" + prefix + "-conformance_results.csv");
                Files.createDirectories(csv.getParent());
                Files.writeString(csv, "Date,Test Id,Description,Expected Result,Actual Result\nnow,8.1.8,CCC,Pass," + (kind.equals("plain") ? "Pass" : "Fail") + "\n");
                Files.createDirectories(temporary.resolve("x509-certs"));
                Files.writeString(temporary.resolve("x509-certs/test-only.txt"), "Synthetic package evidence");
                CompletedTestRun run = new CompletedTestRun(temporary, database, prefix, snapshot);
                // Packaging is exercised before a ResultsPanel is ever constructed/opened.
                Path zip = new ReviewPackageBuilder().build(run);
                try (ZipFile archive = new ZipFile(zip.toFile())) {
                    var summaryEntry = archive.getEntry("logs/conformancelog/" + prefix + "-results-summary.txt");
                    assertNotNull(summaryEntry);
                    String summary = new String(archive.getInputStream(summaryEntry).readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    assertTrue(summary.contains("Cases processed: 1"));
                    if (!kind.equals("plain")) {
                        assertTrue(summary.contains("eliminated tag " + kind));
                        var reference = recorded.references().get(0);
                        assertTrue(summary.contains("Official wording (excerpt):\n“" + reference.excerpt() + "”"));
                        assertTrue(summary.contains("What CCT checks: " + reference.scope()));
                        assertTrue(summary.contains(reference.link()));
                        SwingUtilities.invokeAndWait(() -> {
                            ResultsPanel panel = new ResultsPanel(new AbstractAction("Package Results") {
                                public void actionPerformed(java.awt.event.ActionEvent e) { fail("No desktop action during review"); }
                            }, () -> {});
                            panel.setCompletedRun(run);
                            assertTrue(componentText(panel).contains("Official wording (excerpt)"));
                            assertTrue(componentText(panel).contains("“" + reference.excerpt() + "”"));
                            assertTrue(componentText(panel).contains("What CCT checks"));
                            assertEquals(reference.documentUrl(), button(panel, "Open cited page ↗").getToolTipText());
                        });
                    }
                    assertEquals(1, archive.stream().filter(e -> e.getName().endsWith(".csv")).count());
                }
                assertDoesNotThrow(() -> new ReviewPackageBuilder().build(run), "Repackaging must not duplicate the summary entry");
            } finally { card.reset(); parameters.reset(); }
        }
    }


    /** Exercises source capture from real profile rows; the synthetic outcome does not validate a standard. */
    @ParameterizedTest @CsvSource({
            "PIV_Production_Cards.db,350,3", "PIV_ICAM_Test_Cards.db,350,3",
            "PIV_Production_Cards.db,468,1", "PIV_ICAM_Test_Cards.db,468,1",
            "PIV-I_Production_Cards.db,350,0", "PIV-I_ICAM_Test_Cards.db,350,0"})
    void referencesFollowTheExecutedProfileAndContainer(String profile, int id, int expectedSources) throws Exception {
        Path database = Path.of(System.getProperty("cct.repository"), "conformancelib/testdata", profile);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:file:" + database + "?mode=ro")) {
            TestCaseModel row = new TestCaseModel(new ConformanceTestDatabase(connection));
            row.retrieveForId(id);
            TestStepModel step = row.getSteps().get(0);
            var source = org.junit.platform.engine.support.descriptor.MethodSource.from(step.getTestClassName(),
                    step.getTestMethodName(), "java.lang.String, org.junit.jupiter.api.TestReporter");
            var descriptor = new org.junit.platform.engine.support.descriptor.AbstractTestDescriptor(
                    org.junit.platform.engine.UniqueId.forEngine("metadata").append("test", "source"), "Source capture", source) {
                @Override public Type getType() { return Type.TEST; }
            };
            GuiTestListener listener = new GuiTestListener(false);
            listener.configureCase(row, true);
            listener.testPlanExecutionStarted(null);
            listener.executionFinished(TestIdentifier.from(descriptor), TestExecutionResult.failed(
                    new org.opentest4j.AssertionFailedError("Synthetic metadata outcome")));
            listener.testPlanExecutionFinished(null);
            var sources = listener.completedCases().get(0).steps().get(0).references();
            assertEquals(expectedSources, sources.size());
            if (!sources.isEmpty()) {
                assertEquals("SP 800-78-5", sources.get(0).publication());
                assertTrue(sources.get(0).link().endsWith("#page=16"));
            }
            if (id == 468) assertTrue(sources.stream().noneMatch(r -> r.publication().startsWith("RFC")),
                    "Certificate-specific RFC sources must not be attributed to the CHUID CMS route");
            assertThrows(UnsupportedOperationException.class, () -> sources.clear(), "Run sources are immutable");
        }
    }

    private static String componentText(java.awt.Container parent) {
        StringBuilder text = new StringBuilder();
        for (java.awt.Component child : parent.getComponents()) {
            if (child instanceof JLabel label) text.append(label.getText()).append("\n");
            if (child instanceof javax.swing.text.JTextComponent field) text.append(field.getText()).append("\n");
            if (child instanceof java.awt.Container container) text.append(componentText(container));
        }
        return text.toString();
    }

    private static void execute(String selector, GuiTestListener listener) {
        LauncherFactory.create().execute(LauncherDiscoveryRequestBuilder.request()
                .selectors(DiscoverySelectors.selectMethod(selector)).build(), listener);
    }

    @Test void skippedAndUnrelatedAbortsRemainDistinctFromCardFailures() {
        TestCaseModel row = row("sample", "Vendor reference values", false);
        GuiTestListener listener = new GuiTestListener(false);
        listener.configureCase(row, true);
        listener.testPlanExecutionStarted(null);
        listener.recordOutcome(TestExecutionResult.aborted(
                new gov.gsa.pivconformance.conformancelib.tests.PlaceholderTests.UnsupportedConformanceException("reference")));
        listener.testPlanExecutionFinished(null);
        assertEquals(TestStatus.SKIP, listener.completedCases().get(0).status());
        assertTrue(listener.completedCases().get(0).guidance().contains("vendor"));
        listener.configureCase(row, true);
        listener.testPlanExecutionStarted(null);
        listener.executionFailed(new IllegalStateException("Reader unavailable"));
        RunResults.CaseResult error = listener.completedCases().get(1);
        assertTrue(error.executionError());
        assertEquals("Fail", error.statusText());
        assertEquals(1, error.steps().size(), "Case state must be reset between runs");
    }

    @Test void originalUnsupportedRowPreservesItsReason() throws Exception {
        Path database = Path.of(System.getProperty("cct.repository"), "conformancelib/testdata/PIV_Production_Cards.db");
        try (var connection = DriverManager.getConnection("jdbc:sqlite:file:" + database + "?mode=ro")) {
            TestCaseModel row = new TestCaseModel(new ConformanceTestDatabase(connection));
            row.retrieveForId(143);
            TestStepModel step = row.getSteps().get(0);
            String selector = step.getTestClassName() + "#" + step.getTestMethodName()
                    + "(java.lang.String, org.junit.jupiter.api.TestReporter)";
            ParameterProviderSingleton parameters = ParameterProviderSingleton.getInstance();
            parameters.reset();
            parameters.addContainer(selector, row.getContainer());
            parameters.addNamedParameter(selector, step.getParameters());
            try {
                GuiTestListener listener = new GuiTestListener(false);
                listener.configureCase(row, true);
                execute(selector, listener);
                RunResults.CaseResult result = listener.completedCases().get(0);
                assertEquals(TestStatus.SKIP, result.status());
                assertEquals(1, result.steps().size());
                assertTrue(result.reason().contains("no implemented conformance assertion"));
                assertTrue(result.guidance().contains("vendor"));
                assertFalse(result.guidance().contains("card data is missing"));
            } finally { parameters.reset(); }
        }
    }

    @Test void emptyDiscoveryDoesNotReportPass() {
        GuiTestListener listener = new GuiTestListener(false);
        listener.configureCase(row("empty", "No discovered invocation", true), true);
        listener.testPlanExecutionStarted(null);
        listener.testPlanExecutionFinished(null);
        assertEquals(TestStatus.SKIP, listener.completedCases().get(0).status());
    }

    @Test void assertionsWithUnderlyingParseErrorsRemainAssertionFailures() {
        GuiTestListener listener = new GuiTestListener(false);
        listener.configureCase(row("date", "CHUID date format", true), true);
        listener.testPlanExecutionStarted(null);
        var descriptor = new org.junit.platform.engine.support.descriptor.AbstractTestDescriptor(
                org.junit.platform.engine.UniqueId.forEngine("test").append("test", "date"), "date assertion") {
            @Override public Type getType() { return Type.TEST; }
        };
        var cause = new java.time.format.DateTimeParseException("Invalid month", "20321302", 4);
        var assertion = new org.opentest4j.AssertionFailedError("CHUID date must be YYYYMMDD", cause);
        listener.executionFinished(org.junit.platform.launcher.TestIdentifier.from(descriptor), TestExecutionResult.failed(assertion));
        listener.testPlanExecutionFinished(null);
        RunResults.CaseResult result = listener.completedCases().get(0);
        assertEquals("Fail", result.statusText());
        assertFalse(result.executionError());
        assertTrue(result.reason().contains("CHUID date must be YYYYMMDD"));
    }

    @Test void nativeFiltersAndRunReplacementUseTheRecordedSnapshot() throws Exception {
        var pass = new RunResults.CaseResult("one", "First case", "CCC", true, TestStatus.PASS, List.of());
        var fail = new RunResults.CaseResult("two", "Bad field", "CHUID", true, TestStatus.FAIL, List.of());
        var skip = new RunResults.CaseResult("three", "Needs external image", "Face", true, TestStatus.SKIP, List.of());
        var unexpected = new RunResults.CaseResult("four", "Negative vector", "CCC", false, TestStatus.PASS, List.of());
        RunResults snapshot = new RunResults("test", temporary.resolve("profile.db"), Instant.EPOCH, Instant.EPOCH, true, List.of(pass, fail, skip, unexpected));
        SwingUtilities.invokeAndWait(() -> {
            ResultsPanel panel = new ResultsPanel(new AbstractAction("Package Results") {
                public void actionPerformed(java.awt.event.ActionEvent e) { fail("No package action should run during rendering/filtering"); }
            }, () -> {});
            panel.setCompletedRun(new CompletedTestRun(temporary, snapshot.database(), "one", snapshot));
            assertEquals(3, panel.visibleCount());
            panel.selectFilter(ResultsPanel.Filter.FAILED);
            assertEquals("two", panel.selectedCase().id());
            panel.selectFilter(ResultsPanel.Filter.UNSUPPORTED);
            assertEquals("three", panel.selectedCase().id());
            panel.selectFilter(ResultsPanel.Filter.ALL);
            assertEquals(4, panel.visibleCount());
            panel.search("NEGATIVE");
            assertEquals("four", panel.selectedCase().id());
            panel.search("no match");
            assertEquals(0, panel.visibleCount());
            RunResults replacement = new RunResults("new", temporary.resolve("other-profile.db"), Instant.EPOCH,
                    Instant.EPOCH, true, List.of(pass));
            panel.setCompletedRun(new CompletedTestRun(temporary, replacement.database(), "two", replacement));
            assertEquals(0, panel.visibleCount(), "A new all-pass run has no stale findings");
            panel.selectFilter(ResultsPanel.Filter.ALL);
            assertEquals(1, panel.visibleCount());
            assertEquals("one", panel.selectedCase().id());
            panel.setCompletedRun(null);
            assertEquals(0, panel.visibleCount());
            assertNull(panel.selectedCase());
        });
        assertEquals(2, snapshot.passed()); // One of these passes is unexpected by its negative profile.
        assertTrue(unexpected.expectationMismatch());
        assertTrue(fail.expectationMismatch());
    }

    @Test void interruptedRunSummaryRetainsTheExecutionIssue() throws Exception {
        RunResults results = new RunResults("test", temporary.resolve("profile.db"), Instant.EPOCH,
                Instant.EPOCH.plusSeconds(2), false, List.of(), "Reader connection ended before the first case.");
        String summary = Files.readString(results.writeSummary(temporary, "interrupted"));
        assertTrue(summary.contains("Run: Incomplete"));
        assertTrue(summary.contains("Cases processed: 0"));
        assertTrue(summary.contains("Reader connection ended before the first case."));
    }

    @Test void navigationPreservesFindingsAndBothViewsShareThePackageAction() throws Exception {
        var failure = new RunResults.CaseResult("failure", "Recorded failure", "CCC", true, TestStatus.FAIL, List.of());
        RunResults snapshot = new RunResults("test", temporary.resolve("profile.db"), Instant.EPOCH,
                Instant.EPOCH, true, List.of(failure));
        CompletedTestRun run = new CompletedTestRun(temporary, snapshot.database(), "navigation", snapshot);
        SwingUtilities.invokeAndWait(() -> {
            MainWindowContentPane content = new MainWindowContentPane("1.1.0-rc1");
            JTabbedPane tabs = (JTabbedPane) content.getComponent(0);
            assertEquals(1, tabs.getTabCount(), "Results is hidden until a run has results");
            content.setCompletedRun(run);
            assertEquals(2, tabs.getTabCount());
            content.showResults();
            assertEquals("Results", tabs.getTitleAt(tabs.getSelectedIndex()));
            ResultsPanel results = (ResultsPanel) tabs.getSelectedComponent();
            results.selectFilter(ResultsPanel.Filter.FAILED);
            results.search("failure");
            button(results, "Back to Testing").doClick();
            assertEquals("Testing", tabs.getTitleAt(tabs.getSelectedIndex()));
            content.showResults();
            assertEquals("failure", results.selectedCase().id());
            assertSame(button(content.getTestExecutionPanel(), "Package Results").getAction(),
                    button(results, "Package Results").getAction());
            var latestCase = new RunResults.CaseResult("latest", "Second run", "CCC", true, TestStatus.PASS, List.of());
            var latest = new RunResults("test", temporary.resolve("second.db"), Instant.EPOCH,
                    Instant.EPOCH, true, List.of(latestCase));
            content.setCompletedRun(new CompletedTestRun(temporary, latest.database(), "second", latest));
            assertSame(results, tabs.getSelectedComponent(), "The open Results view receives the replacement snapshot");
            results.selectFilter(ResultsPanel.Filter.ALL);
            assertEquals("latest", results.selectedCase().id());
            content.setCompletedRun(null);
            assertEquals(0, tabs.getSelectedIndex());
            assertEquals(1, tabs.getTabCount());

            PackageResultsAction action = new PackageResultsAction("Package Results", null, "");
            action.setCompletedRun(run);
            var dismissed = new java.util.concurrent.atomic.AtomicBoolean();
            var completion = action.completionContent(temporary.resolve("test-results.zip"), () -> dismissed.set(true));
            assertTrue(button(completion.panel(), "Show in Folder").isEnabled());
            assertTrue(button(completion.panel(), "Copy Path").isEnabled());
            assertTrue(button(completion.panel(), "View Results").isEnabled());
            completion.done().doClick();
            assertTrue(dismissed.get());
        });
    }

    @Test void displayedVerdictsAndFiltersMatchExistingCctStatuses() throws Exception {
        var error = new RunResults.StepResult("reader", TestStatus.FAIL, true, "Reader error", "", "", "", List.of());
        var cases = List.of(
                new RunResults.CaseResult("pass", "Positive", "CCC", true, TestStatus.PASS, List.of()),
                new RunResults.CaseResult("fail", "Positive failure", "CCC", true, TestStatus.FAIL, List.of()),
                new RunResults.CaseResult("expected", "Negative failure", "CCC", false, TestStatus.FAIL, List.of()),
                new RunResults.CaseResult("unexpected", "Negative pass", "CCC", false, TestStatus.PASS, List.of()),
                new RunResults.CaseResult("error", "Negative execution error", "CCC", false, TestStatus.FAIL, List.of(error)),
                new RunResults.CaseResult("skip", "Unsupported", "CCC", true, TestStatus.SKIP, List.of()));
        RunResults snapshot = new RunResults("test", temporary.resolve("profile.db"), Instant.EPOCH,
                Instant.EPOCH, true, cases);
        assertEquals(2, snapshot.passed());
        assertEquals(3, snapshot.failed());
        assertEquals(1, snapshot.unsupported());
        String summary = Files.readString(snapshot.writeSummary(temporary, "labels"));
        assertTrue(summary.contains("Pass: 2\nFail: 3\nUnsupported: 1"));
        assertFalse(summary.contains("Unexpected results:"));
        SwingUtilities.invokeAndWait(() -> {
            ResultsPanel panel = new ResultsPanel(new PackageResultsAction("Package Results", null, ""), () -> {});
            panel.setCompletedRun(new CompletedTestRun(temporary, snapshot.database(), "unexpected", snapshot));
            assertEquals(5, panel.visibleCount());
            assertNull(button(panel, "Unexpected: 3"), "A profile comparison is not another result category");
            button(panel, "Unsupported: 1").doClick();
            assertEquals("skip", panel.selectedCase().id());
            button(panel, "Fail: 3").doClick();
            assertEquals(3, panel.visibleCount());
            button(panel, "Pass: 2").doClick();
            assertEquals(2, panel.visibleCount());
            assertEquals("Fail", cases.get(2).statusText(), "An expected negative retains the actual Fail verdict");
            assertEquals("Pass", cases.get(3).statusText(), "A profile mismatch retains the actual Pass verdict");
            assertEquals("Fail", cases.get(4).statusText(), "An execution error retains CCT's Fail verdict");
            assertTrue(cases.get(4).executionError());
            assertEquals("Unsupported", cases.get(5).statusText());
        });
    }

    @Test void testingFormAlignsThePinAndKeepsActionsWithinTheWorkspace() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            SimpleTestExecutionPanel panel = new SimpleTestExecutionPanel();
            panel.setPostRunActionsVisible(true);
            panel.setSize(800, 650);
            layout(panel);
            javax.swing.JPasswordField pin = findPin(panel);
            assertNotNull(pin);
            assertEquals(panel.getReaderComboBox().getX(), pin.getX());
            assertTrue(pin.getWidth() < panel.getReaderComboBox().getWidth());
            JButton refresh = button(panel, "Refresh Readers");
            assertTrue(refresh.getWidth() < panel.getReaderComboBox().getWidth(), "Refresh should use its natural width");
            for (String text : List.of("Verify PIN and Execute Tests", "View Test Results", "Package Results")) {
                JButton action = button(panel, text);
                java.awt.Point point = SwingUtilities.convertPoint(action.getParent(), action.getLocation(), panel);
                assertTrue(point.x >= 0 && point.x + action.getWidth() <= panel.getWidth(), text);
                assertEquals(refresh.getHeight(), action.getHeight(), text);
            }
        });
    }

    private static void layout(java.awt.Container parent) {
        parent.doLayout();
        for (java.awt.Component child : parent.getComponents())
            if (child instanceof java.awt.Container container) layout(container);
    }

    private static JPasswordField findPin(java.awt.Container parent) {
        for (java.awt.Component child : parent.getComponents()) {
            if (child instanceof JPasswordField pin) return pin;
            if (child instanceof java.awt.Container container) {
                JPasswordField pin = findPin(container);
                if (pin != null) return pin;
            }
        }
        return null;
    }

    @Test void unimplementedKeyHistoryDoesNotImplyThatTheObjectWasAbsent() {
        var step = new RunResults.StepResult("placeholder", TestStatus.SKIP, false,
                "CCT has no implemented conformance assertion for Key History", "", "", "", List.of());
        var result = new RunResults.CaseResult("sample", "Key History", "KEY_HISTORY_OBJECT_OID", true,
                TestStatus.SKIP, List.of(step));
        assertFalse(result.guidance().contains("object was unavailable"));
        assertTrue(result.guidance().contains("not implemented"));
    }

    private static JButton button(java.awt.Container parent, String text) {
        for (java.awt.Component child : parent.getComponents()) {
            if (child instanceof JButton button && (text.equals(button.getText())
                    || text.equals(button.getAccessibleContext().getAccessibleName()))) return button;
            if (child instanceof java.awt.Container container) {
                JButton found = button(container, text);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static TestCaseModel row(String id, String description, boolean expectedPass) {
        TestCaseModel row = new TestCaseModel(null);
        row.setIdentifier(id); row.setDescription(description); row.setContainer("DISCOVERY_OBJECT_OID");
        row.setExpectedStatus(expectedPass ? 1 : 0);
        return row;
    }
    private static byte[] join(byte[] a, byte[] b) {
        byte[] joined = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, joined, a.length, b.length);
        return joined;
    }
}
