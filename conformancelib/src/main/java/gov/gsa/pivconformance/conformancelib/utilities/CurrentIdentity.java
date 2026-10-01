package gov.gsa.pivconformance.conformancelib.utilities;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import static gov.gsa.pivconformance.conformancelib.utilities.CurrentDataModel.require;

/** SP800-73-5 Part1 3.4.1 item 4; RFC4122 section 3. */
public final class CurrentIdentity {
    private CurrentIdentity() { }
    public static void cardUuid(byte[] generalNamesDer, byte[] expectedGuid) {
        String rule="73-UUID-CERT-LINK";
        CurrentDataModel.uuid(expectedGuid,false);
        require(generalNamesDer!=null,rule,"SAN extension required");
        boolean match=false;
        try {
            for (GeneralName name:GeneralNames.getInstance(generalNamesDer).getNames()) {
                if (name.getTagNo()!=GeneralName.uniformResourceIdentifier) continue;
                String uri=DERIA5String.getInstance(name.getName()).getString();
                if (!uri.matches("(?i)urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) continue;
                UUID uuid=UUID.fromString(uri.substring(9));
                byte[] value=ByteBuffer.allocate(16).putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits()).array();
                if (Arrays.equals(value,expectedGuid)) match=true;
            }
        } catch (Exception e) { throw new AssertionError(rule+": malformed SAN",e); }
        require(match,rule,"no UUID URI matches the CHUID GUID");
    }
}
