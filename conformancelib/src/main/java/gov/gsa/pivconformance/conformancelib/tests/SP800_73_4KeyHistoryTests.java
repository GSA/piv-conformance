package gov.gsa.pivconformance.conformancelib.tests;

import gov.gsa.pivconformance.conformancelib.configuration.ResultReference;

import gov.gsa.pivconformance.cardlib.card.client.KeyHistoryObject;
import gov.gsa.pivconformance.cardlib.tlv.BerTag;
import gov.gsa.pivconformance.cardlib.tlv.TagConstants;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterizedArgumentsProvider;
import gov.gsa.pivconformance.conformancelib.utilities.AtomHelper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.TestReporter;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SP 800-73-5 Part 1 section 3.3.3 and Table 20; the object also existed in 73-4. */
public class SP800_73_4KeyHistoryTests {
    @DisplayName("SP800-73 Key History object fields")
    @ParameterizedTest(name = "{index} => oid = {0}")
    @ArgumentsSource(ParameterizedArgumentsProvider.class)
    @ResultReference(publication = "SP 800-73-5 Part 1",
            location = "Section 3.3.3, pp. 13 through 14; Appendix A, Table 20, p. 38",
            url = "https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final",
            documentUrl = "https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf#page=25",
            excerpt = "The Key History object SHALL be present in the PIV Card Application if the PIV Card Application contains any retired key management private keys but MAY be present even if no such keys are present in the PIV Card Application.",
            scope = "Checks present Key History fields, count bounds and conditional URL format. An absent object cannot establish whether retired private keys exist. This case does not retrieve off-card certificates.")
    void sp800_73_4_Test_57(String oid, TestReporter reporter) throws Exception {
        KeyHistoryObject object = (KeyHistoryObject) AtomHelper.getDataObject(oid);
        if (object == null) throw new PlaceholderTests.UnsupportedConformanceException(
                "absent optional Key History; retired private-key presence cannot be established from card data");
        int onCard = object.getKeysWithOnCardCerts();
        int offCard = object.getKeysWithOffCardCerts();
        assertTrue(onCard >= 0 && offCard >= 0 && onCard + offCard <= 20,
                "SP800-73 Key History: retired key count must be no greater than 20");

        byte[] url = object.getOffCardCertUrl();
        List<BerTag> expected = new ArrayList<>(Arrays.asList(
                new BerTag(TagConstants.KEYS_WITH_ON_CARD_CERTS_TAG),
                new BerTag(TagConstants.KEYS_WITH_OFF_CARD_CERTS_TAG)));
        if (url != null) expected.add(new BerTag(TagConstants.OFF_CARD_CERT_URL_TAG));
        expected.add(new BerTag(TagConstants.ERROR_DETECTION_CODE_TAG));
        assertEquals(expected, object.getTagList(),
                "SP800-73 Key History: expected C1, C2, conditional F3, FE in order");
        assertTrue(object.inBounds(oid), "SP800-73 Key History: field length exceeds Table 20");

        assertTrue(offCard == 0 || url != null,
                "SP800-73 Key History: offCardCertURL is required when off-card count is nonzero");
        assertTrue(onCard != 0 || offCard != 0 || url == null,
                "SP800-73 Key History: offCardCertURL must be absent when both counts are zero");
        if (url != null) {
            String value = new String(url, StandardCharsets.US_ASCII);
            // RFC 3986 section 3.2.2 permits a final root dot in a DNS host name.
            String dnsLabel = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
            assertTrue(Arrays.equals(url, value.getBytes(StandardCharsets.US_ASCII))
                            && value.matches("http://" + dnsLabel + "(?:\\." + dnsLabel + ")*\\.?/[0-9A-Fa-f]{64}"),
                    "SP800-73 Key History: offCardCertURL must be an HTTP DNS name and SHA-256 hex hash");
            // RFC 3986 section 3.2.2 classifies a matching IPv4 host as a literal.
            String host = value.substring(7, value.indexOf('/', 7));
            assertTrue(!org.bouncycastle.util.IPAddress.isValidIPv4(host),
                    "SP800-73 Key History: offCardCertURL host must be a DNS name");
        }
    }
}
