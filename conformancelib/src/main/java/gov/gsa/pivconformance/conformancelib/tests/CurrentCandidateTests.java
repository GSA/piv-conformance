package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.cardlib.card.client.PIVDataObject;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import gov.gsa.pivconformance.conformancelib.utilities.CurrentDataModel;
import gov.gsa.pivconformance.conformancelib.utilities.CurrentCrypto;
import org.bouncycastle.cert.X509CertificateHolder;
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

    private X509CertificateHolder certificate(String oid) {
        try { return new X509CertificateHolder(CurrentDataModel.certificateBytes(required(oid))); }
        catch (Exception e) { throw new AssertionError("CANDIDATE-INPUT: invalid certificate encoding", e); }
    }

    @ParameterizedTest @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void cardKey(String oid, TestReporter reporter) throws java.io.IOException {
        CurrentCrypto.cardKey(certificate(oid).getSubjectPublicKeyInfo().getEncoded());
    }

    @ParameterizedTest @ArgumentsSource(ParameterizedArgumentsProvider.class)
    void certificateSignature(String oid, TestReporter reporter) throws java.io.IOException {
        var cert = certificate(oid);
        CurrentCrypto.signatureAlgorithm(cert.getSignatureAlgorithm().getEncoded());
        CurrentDataModel.require(cert.getSignatureAlgorithm().equals(cert.toASN1Structure().getTBSCertificate().getSignature()),
                "78-CERT-SIGNATURE", "inner and outer certificate algorithm identifiers differ (RFC5280 4.1.1.2)");
    }
}
