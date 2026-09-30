package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.conformancelib.utilities.CurrentDataModel;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

/** Explicit CURRENT_2026_CANDIDATE database entry points; historical atoms are unchanged. */
public class CurrentCandidateTests {
    private byte[] required(String oid) {
        PIVDataObject object = AtomHelper.getRawDataObject(oid);
        CurrentDataModel.require(object != null, "CANDIDATE-INPUT", "required object unavailable: " + oid);
        return object.getBytes();
    }

    @ParameterizedTest @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void ccc(String oid, TestReporter reporter) { CurrentDataModel.ccc(required(oid)); }

    @ParameterizedTest @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void chuid(String oid, TestReporter reporter) { CurrentDataModel.chuid(required(oid)); }

    @ParameterizedTest @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void certificateObject(String oid, TestReporter reporter) { CurrentDataModel.certificateObject(required(oid)); }

    @ParameterizedTest @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void securityObject(String oid, TestReporter reporter) { CurrentDataModel.securityObject(required(oid)); }

    @ParameterizedTest @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void keyHistory(String oid, TestReporter reporter) {
        PIVDataObject object = AtomHelper.getRawDataObject(oid);
        Assumptions.assumeTrue(object != null, "Optional object absent; retired-key applicability not established");
        CurrentDataModel.keyHistory(object.getBytes());
    }
}
