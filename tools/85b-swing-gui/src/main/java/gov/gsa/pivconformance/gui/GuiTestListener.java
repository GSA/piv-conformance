package gov.gsa.pivconformance.gui;

import gov.gsa.pivconformance.conformancelib.configuration.ResultReference;
import gov.gsa.pivconformance.conformancelib.configuration.TestCaseModel;
import gov.gsa.pivconformance.conformancelib.configuration.TestStatus;
import gov.gsa.pivconformance.conformancelib.tests.PlaceholderTests;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.engine.reporting.ReportEntry;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;
import org.opentest4j.AssertionFailedError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/** Records the original CCT verdicts and their causes as each database case executes. */
public class GuiTestListener implements TestExecutionListener {
    private static final Logger LOG = LoggerFactory.getLogger(GuiTestListener.class);
    private static final Logger PROGRESS = LoggerFactory.getLogger("gov.gsa.pivconformance.conformancelib.testProgress");
    private static final Logger RESULTS = LoggerFactory.getLogger("gov.gsa.pivconformance.conformancelib.testResult");

    private String identifier = "";
    private String description = "";
    private String object = "";
    private boolean expectedPass = true;
    private boolean reportCase = true;
    private String configurationError;
    private JProgressBar progressBar;
    private final boolean updateUi;
    private boolean failed;
    private boolean aborted;
    private boolean unsupported;
    private int invocations;
    private final List<RunResults.StepResult> steps = new ArrayList<>();
    private final List<RunResults.CaseResult> completedCases = new ArrayList<>();
    private final Set<Throwable> recordedFailures = Collections.newSetFromMap(new IdentityHashMap<>());

    public GuiTestListener() { this(true); }
    GuiTestListener(boolean updateUi) { this.updateUi = updateUi; }

    void configureCase(TestCaseModel testCase, boolean reportCase) {
        identifier = testCase.getIdentifier();
        description = testCase.getDescription();
        object = testCase.getContainer();
        expectedPass = testCase.getExpectedStatus() == 1;
        this.reportCase = reportCase;
        configurationError = null;
        failed = aborted = unsupported = false;
        steps.clear();
        recordedFailures.clear();
        invocations = 0;
    }

    void configurationFailed(String reason) { configurationError = reason; }
    List<RunResults.CaseResult> completedCases() { return List.copyOf(completedCases); }

    @Override public void testPlanExecutionStarted(TestPlan plan) {
        failed = aborted = unsupported = false;
        invocations = 0;
        steps.clear();
        recordedFailures.clear();
        if (configurationError != null) {
            failed = true;
            steps.add(new RunResults.StepResult("Profile configuration", TestStatus.FAIL, true,
                    configurationError, "", "", configurationError, List.of()));
        }
        PROGRESS.info("Test plan started for conformance test {}{}", identifier, reportCase ? "" : " (setup)");
        onUi(() -> { if (progressBar != null) progressBar.setString(identifier); });
    }

    @Override public void testPlanExecutionFinished(TestPlan plan) {
        if (invocations == 0 && !failed && !aborted && steps.isEmpty()) {
            unsupported = true;
            steps.add(new RunResults.StepResult("JUnit discovery", TestStatus.SKIP, false,
                    "No test assertions executed for this case. Review the selected profile's method mappings.",
                    "", "", "No test invocations were reported by JUnit.", List.of()));
        }
        PROGRESS.info("Test plan finished for conformance test {}", identifier);
        publishCase();
    }

    void executionFailed(Throwable failure) {
        failed = true;
        steps.add(new RunResults.StepResult("JUnit execution", TestStatus.FAIL, true,
                "CCT could not execute this case: " + failure, "", "", technical(failure), List.of()));
        publishCase();
    }

    private void publishCase() {
        if (!reportCase) return; // The preliminary CHUID read is setup, not another result row.
        TestStatus status = getResultStatus();
        completedCases.add(new RunResults.CaseResult(identifier, description, object, expectedPass, status, steps));
        RESULTS.info("{},\"{}\",{},{}", identifier, description.replace('"', '\''),
                expectedPass ? "Pass" : "Fail", status == TestStatus.SKIP ? "Unsupported" : status == TestStatus.FAIL ? "Fail" : "Pass");
        onUi(() -> {
            if (progressBar != null) {
                progressBar.setString(identifier + " Finished.");
                progressBar.setValue(progressBar.getValue() + 1);
            }
            GuiRunnerApplication app = GuiRunnerAppController.getInstance().getApp();
            if (app == null) return;
            GuiTestCaseTreeNode node = app.getTreePanel().getNodeByName(identifier);
            if (node != null && node.getTestCase() != null) {
                node.getTestCase().setTestStatus(status);
                if (app.getTreePanel().getTreeModel() != null) app.getTreePanel().getTreeModel().nodeChanged(node);
            }
        });
    }

    @Override public void executionStarted(TestIdentifier test) {
        if (!test.isTest()) return;
        PROGRESS.info("Started {}:{}", identifier, test.getDisplayName());
        onUi(() -> { if (progressBar != null) progressBar.setString(identifier + " (" + test.getDisplayName() + ")"); });
    }

    @Override public void reportingEntryPublished(TestIdentifier test, ReportEntry entry) {
        PROGRESS.info("Case {} step {}: {}", identifier, methodName(test), entry.getKeyValuePairs());
    }

    @Override public void executionSkipped(TestIdentifier test, String reason) {
        unsupported = true;
        steps.add(new RunResults.StepResult(methodName(test), TestStatus.SKIP, false,
                "JUnit skipped this step: " + reason, "", "", reason, references(test)));
    }

    @Override public void executionFinished(TestIdentifier test, TestExecutionResult result) {
        recordOutcome(result);
        if (test.isTest()) invocations++;
        Throwable throwable = result.getThrowable().orElse(null);
        // Successful engine/template callbacks are not extra assertions. Keep setup/container errors.
        if (!test.isTest() && result.getStatus() == TestExecutionResult.Status.SUCCESSFUL) return;
        if (throwable != null && !recordedFailures.add(throwable)) return;
        TestStatus status = isUnsupportedResult(result) ? TestStatus.SKIP
                : result.getStatus() == TestExecutionResult.Status.SUCCESSFUL ? TestStatus.PASS : TestStatus.FAIL;
        Throwable root = rootCause(throwable);
        AssertionError assertionError = findCause(throwable, AssertionError.class);
        if (assertionError != null) root = assertionError;
        boolean executionError = status == TestStatus.FAIL && assertionError == null;
        String reason = throwable == null ? (status == TestStatus.PASS ? "" : "JUnit did not record a failure cause.")
                : root.getMessage() == null ? root.getClass().getSimpleName() : root.getMessage();
        AssertionFailedError assertion = findCause(throwable, AssertionFailedError.class);
        String expected = assertion != null && assertion.isExpectedDefined() ? assertion.getExpected().getStringRepresentation() : "";
        String actual = assertion != null && assertion.isActualDefined() ? assertion.getActual().getStringRepresentation() : "";
        steps.add(new RunResults.StepResult(methodName(test), status, executionError, limit(reason, 8000),
                limit(expected, 1000), limit(actual, 1000), technical(throwable), references(test)));
        if (throwable != null) LOG.error("Case {} step {}: {}", identifier, methodName(test), reason, throwable);
        PROGRESS.info("Finished {}:{}", identifier, test.getDisplayName());
    }

    void recordOutcome(TestExecutionResult result) {
        if (result.getStatus() == TestExecutionResult.Status.FAILED) failed = true;
        if (result.getStatus() == TestExecutionResult.Status.ABORTED) {
            if (isUnsupportedResult(result)) unsupported = true;
            else aborted = true;
        }
    }

    private boolean isUnsupportedResult(TestExecutionResult result) {
        return result.getStatus() == TestExecutionResult.Status.ABORTED
                && result.getThrowable().filter(PlaceholderTests.UnsupportedConformanceException.class::isInstance).isPresent();
    }

    TestStatus getResultStatus() { return aborted || failed ? TestStatus.FAIL : unsupported ? TestStatus.SKIP : TestStatus.PASS; }

    private static String methodName(TestIdentifier test) {
        return test.getSource().filter(MethodSource.class::isInstance).map(MethodSource.class::cast)
                .map(m -> m.getClassName() + "#" + m.getMethodName()).orElse(test.getDisplayName());
    }

    private List<RunResults.Reference> references(TestIdentifier test) {
        try {
            ResultReference[] refs = test.getSource().filter(MethodSource.class::isInstance).map(MethodSource.class::cast)
                    .map(m -> m.getJavaMethod().getAnnotationsByType(ResultReference.class)).orElse(new ResultReference[0]);
            return java.util.Arrays.stream(refs)
                    .filter(ref -> ref.containers().length == 0 || java.util.Arrays.asList(ref.containers()).contains(object))
                    .map(ref -> new RunResults.Reference(ref.publication(), ref.location(), ref.url(), ref.scope(),
                            ref.excerpt(), ref.documentUrl())).toList();
        } catch (RuntimeException e) {
            LOG.warn("Unable to resolve source metadata for {}", methodName(test), e);
            return List.of();
        }
    }

    private static Throwable rootCause(Throwable t) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        while (t != null && t.getCause() != null && seen.add(t.getCause())) t = t.getCause();
        return t;
    }

    private static <T extends Throwable> T findCause(Throwable failure, Class<T> type) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        while (failure != null && seen.add(failure)) {
            if (type.isInstance(failure)) return type.cast(failure);
            failure = failure.getCause();
        }
        return null;
    }

    private static String technical(Throwable t) {
        if (t == null) return "";
        StringBuilder text = new StringBuilder(t.toString());
        for (StackTraceElement frame : t.getStackTrace()) {
            if (text.length() > 4000) break;
            text.append("\n  at ").append(frame);
        }
        return limit(text.toString(), 4500);
    }

    private static String limit(String value, int length) {
        if (value == null) return "";
        return value.length() > length ? value.substring(0, length) + "\n[truncated; see debug log]" : value;
    }

    private void onUi(Runnable action) {
        if (!updateUi) return;
        try {
            if (SwingUtilities.isEventDispatchThread()) action.run();
            else SwingUtilities.invokeAndWait(action);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.error("Interrupted while updating case progress", e);
        } catch (InvocationTargetException e) { LOG.error("Unable to update case progress", e.getCause()); }
    }

    public String getTestCaseIdentifier() { return identifier; }
    public void setTestCaseIdentifier(String value) { identifier = value; }
    public String getTestCaseDescription() { return description; }
    public void setTestCaseDescription(String value) { description = value; }
    public boolean getTestCaseExpectedResult() { return expectedPass; }
    public void setTestCaseExpectedResult(boolean value) { expectedPass = value; }
    public JProgressBar getProgressBar() { return progressBar; }
    public void setProgressBar(JProgressBar value) { progressBar = value; }
}
