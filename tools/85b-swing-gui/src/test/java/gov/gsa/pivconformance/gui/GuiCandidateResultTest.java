package gov.gsa.pivconformance.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;
import gov.gsa.pivconformance.conformancelib.configuration.TestStatus;

class GuiCandidateResultTest {
    @Test void absentConditionalCandidateIsSkipped() {
        GuiTestListener listener = new GuiTestListener();
        listener.setTestCaseIdentifier("CANDIDATE.5");
        listener.m_atomAborted = true;
        assertEquals(TestStatus.SKIP,listener.resultStatus());
    }

    @Test void candidateAssertionFailureTakesPriority() {
        GuiTestListener listener = new GuiTestListener();
        listener.setTestCaseIdentifier("CANDIDATE.5");
        listener.m_atomAborted = true;
        listener.m_atomFailed = true;
        assertEquals(TestStatus.FAIL,listener.resultStatus());
    }

    @Test void historicalAbortKeepsHistoricalBehavior() {
        GuiTestListener listener = new GuiTestListener();
        listener.setTestCaseIdentifier("8.1.1");
        listener.m_atomAborted = true;
        assertEquals(TestStatus.FAIL,listener.resultStatus());
    }

    @Test void successfulCandidatePasses() {
        GuiTestListener listener = new GuiTestListener();
        listener.setTestCaseIdentifier("CANDIDATE.5");
        assertEquals(TestStatus.PASS,listener.resultStatus());
    }
}
