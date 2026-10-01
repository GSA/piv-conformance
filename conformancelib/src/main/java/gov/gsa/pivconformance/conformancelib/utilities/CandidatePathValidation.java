package gov.gsa.pivconformance.conformancelib.utilities;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;

/** Offline candidate PKIX path/policy evidence, RFC5280 section 6.
 * Explicit trust, policy and time are required; revocation is NOT evaluated.
 * Historical Validator behavior and the installed trust store are untouched.
 */
public final class CandidatePathValidation {
    private CandidatePathValidation() { }
    public static CertPath validate(X509Certificate leaf, X509Certificate root,
                                    Collection<X509Certificate> intermediates, String policy,
                                    Instant time, String provider) throws GeneralSecurityException {
        Objects.requireNonNull(leaf); Objects.requireNonNull(root);
        Objects.requireNonNull(intermediates); Objects.requireNonNull(time);
        if (policy == null || policy.isBlank()) throw new IllegalArgumentException("Explicit policy required");
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(leaf);
        PKIXBuilderParameters params = new PKIXBuilderParameters(Set.of(new TrustAnchor(root,null)),selector);
        params.setDate(Date.from(time));
        params.setInitialPolicies(Set.of(policy));
        params.setExplicitPolicyRequired(true);
        params.setRevocationEnabled(false);
        List<X509Certificate> certificates = new ArrayList<>(intermediates);
        certificates.add(leaf);
        params.addCertStore(CertStore.getInstance("Collection",new CollectionCertStoreParameters(certificates),provider));
        return CertPathBuilder.getInstance("PKIX",provider).build(params).getCertPath();
    }
}
