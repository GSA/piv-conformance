package gov.gsa.pivconformance.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.platform.engine.TestExecutionResult;

import gov.gsa.pivconformance.conformancelib.configuration.TestStatus;
import gov.gsa.pivconformance.conformancelib.tests.PlaceholderTests;

class GuiTestListenerTest {
    @Test
    void unsupportedPlaceholderIsSkippedRatherThanPassedOrBlamedOnCard() {
        GuiTestListener listener = new GuiTestListener();
        listener.recordOutcome(TestExecutionResult.aborted(
                new PlaceholderTests.UnsupportedConformanceException("KEY_HISTORY_OBJECT_OID")));
        assertEquals(TestStatus.SKIP, listener.getResultStatus());

        listener.recordOutcome(TestExecutionResult.failed(new AssertionError("Real assertion failure")));
        assertEquals(TestStatus.FAIL, listener.getResultStatus());
    }

    @Test
    void otherOutcomesRetainTheirExistingMeaning() {
        GuiTestListener listener = new GuiTestListener();
        listener.recordOutcome(TestExecutionResult.successful());
        assertEquals(TestStatus.PASS, listener.getResultStatus());

        listener.recordOutcome(TestExecutionResult.aborted(new RuntimeException("Acquisition error")));
        assertEquals(TestStatus.FAIL, listener.getResultStatus());

        GuiTestListener misleadingMessage = new GuiTestListener();
        misleadingMessage.recordOutcome(TestExecutionResult.aborted(new RuntimeException(
                PlaceholderTests.UNSUPPORTED_MESSAGE + "but this is an unrelated abort")));
        assertEquals(TestStatus.FAIL, misleadingMessage.getResultStatus());

        GuiTestListener mixed = new GuiTestListener();
        mixed.recordOutcome(TestExecutionResult.aborted(
                new PlaceholderTests.UnsupportedConformanceException("one case")));
        mixed.recordOutcome(TestExecutionResult.aborted(new RuntimeException("Another atom aborted")));
        assertEquals(TestStatus.FAIL, mixed.getResultStatus());
    }
}
