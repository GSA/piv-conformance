package gov.gsa.pivconformance.conformancelib.utilities;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.*;

/** Selected SP 800-73-5 Part 1 assertions. Not a complete card conformance verdict. */
public final class CurrentDataModel {
    private CurrentDataModel() { }

    public static void require(boolean value, String rule, String detail) {
        if (!value) throw new AssertionError(rule + ": " + detail);
    }

    private record Element(int tag, byte[] value) { }

    // All supported Appendix A fields have single-octet tags. The input is the
    // entire GET DATA response value (53 wrapper), excluding the APDU status word.
    private static List<Element> parse(byte[] bytes, String rule) {
        require(bytes != null, rule, "missing object");
        List<Element> result = new ArrayList<>();
        int p = 0;
        while (p < bytes.length) {
            int tag = bytes[p++] & 255;
            require((tag & 31) != 31 && tag != 0 && tag != 255, rule, "unsupported field tag");
            require(p < bytes.length, rule, "missing length");
            int first = bytes[p++] & 255;
            long size = first;
            if ((first & 128) != 0) {
                int count = first & 127;
                require(count > 0 && count <= 4 && count <= bytes.length - p,
                        rule, "invalid or truncated definite length");
                size = 0;
                for (int i = 0; i < count; i++) size = (size << 8) | (bytes[p++] & 255);
            }
            require(size <= bytes.length - p, rule, "truncated value");
            result.add(new Element(tag, Arrays.copyOfRange(bytes, p, p + (int) size)));
            p += (int) size;
        }
        return result;
    }

    private static Map<Integer, byte[]> fields(byte[] bytes, String rule, int[] order, Set<Integer> optional) {
        List<Element> outer = parse(bytes, rule);
        require(outer.size() == 1 && outer.get(0).tag == 0x53, rule, "expected one 53 wrapper");
        List<Element> inner = parse(outer.get(0).value, rule);
        Map<Integer, byte[]> result = new LinkedHashMap<>();
        int previous = -1;
        for (Element e : inner) {
            int index = -1;
            for (int i = 0; i < order.length; i++) if (order[i] == e.tag) index = i;
            require(index >= 0, rule, "unlisted or removed tag " + Integer.toHexString(e.tag));
            require(index > previous, rule, "duplicate or out-of-order tag");
            previous = index;
            result.put(e.tag, e.value);
        }
        for (int tag : order) require(optional.contains(tag) || result.containsKey(tag), rule,
                "missing mandatory tag " + Integer.toHexString(tag));
        if (result.containsKey(0xfe)) length(result, 0xfe, rule, 0);
        return result;
    }

    private static void length(Map<Integer, byte[]> fields, int tag, String rule, int... allowed) {
        int n = fields.get(tag).length;
        require(Arrays.stream(allowed).anyMatch(x -> x == n), rule,
                "invalid length for tag " + Integer.toHexString(tag));
    }

    /** Appendix A Table 9 and section 3.1.1. */
    public static void ccc(byte[] bytes) {
        String rule = "73-CCC-FIELDS";
        Map<Integer, byte[]> f = fields(bytes, rule,
                new int[]{0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xfa,0xfb,0xfc,0xfd,0xfe}, Set.of());
        length(f, 0xf0, rule, 0, 21);
        for (int t : new int[]{0xf1,0xf2,0xf4}) length(f,t,rule,0,1);
        require(f.get(0xf3).length <= 128, rule, "CardURL exceeds 128 bytes");
        length(f,0xf5,rule,1);
        require(f.get(0xf5)[0] == 0x10, rule, "registered data model must be 10");
        length(f,0xf6,rule,0,17);
        for (int t : new int[]{0xf7,0xfa,0xfb,0xfc,0xfd}) length(f,t,rule,0);
    }

    /** Table 10; section 3.4.1 item 1 and 3.4.2. Does not verify CMS or FASC-N content. */
    public static void chuid(byte[] bytes) {
        String rule = "73-CHUID-FIELDS";
        Map<Integer, byte[]> f = fields(bytes, rule, new int[]{0x30,0x34,0x35,0x36,0x3e,0xfe}, Set.of(0x36));
        length(f,0x30,rule,25);
        require(f.get(0x3e).length <= 2816, rule, "signature value exceeds 2816 bytes");
        uuid(f.get(0x34), false);
        if (f.containsKey(0x36)) uuid(f.get(0x36), true);
        byte[] date = f.get(0x35);
        require(date.length == 8, "73-CHUID-DATE", "date must have eight bytes");
        for (byte b : date) require(b >= '0' && b <= '9', "73-CHUID-DATE", "date is not ASCII digits");
        try {
            LocalDate.parse(new String(date, StandardCharsets.US_ASCII),
                    DateTimeFormatter.ofPattern("uuuuMMdd").withResolverStyle(ResolverStyle.STRICT));
        } catch (DateTimeParseException e) {
            throw new AssertionError("73-CHUID-DATE: invalid calendar date", e);
        }
    }

    public static void uuid(byte[] value, boolean holder) {
        String rule = holder ? "73-HOLDER-UUID" : "73-CARD-UUID";
        require(value != null && value.length == 16, rule, "UUID must have sixteen bytes");
        int version = (value[6] & 255) >>> 4;
        require((value[8] & 0xc0) == 0x80, rule, "RFC4122 variant required");
        require(holder ? version == 4 : version == 1 || version == 4 || version == 5,
                rule, "disallowed UUID version");
    }

    public static byte[] chuidField(byte[] bytes,int tag) {
        chuid(bytes);
        Map<Integer,byte[]> f=fields(bytes,"73-CHUID-FIELDS",new int[]{0x30,0x34,0x35,0x36,0x3e,0xfe},Set.of(0x36));
        require(f.containsKey(tag),"73-CHUID-FIELDS","requested field missing");
        return f.get(tag).clone();
    }

    public static byte[] biometricValue(byte[] bytes) {
        return fields(bytes,"76-CBEFF-HEADER",new int[]{0xbc,0xfe},Set.of()).get(0xbc);
    }

    /** Tables 11,16-18,21-40. 1856 is a recommendation, not a maximum. */
    public static void certificateObject(byte[] bytes) {
        String rule = "73-CERT-FIELDS";
        Map<Integer, byte[]> f = fields(bytes,rule,new int[]{0x70,0x71,0xfe},Set.of());
        length(f,0x71,rule,1);
        require(f.get(0x71)[0] == 0 || f.get(0x71)[0] == 1,rule,"CertInfo must be 00 or 01");
        // Certificate parsing, compression validity and signature are separate assertions.
    }

    /** Extract a certificate after current-profile TLV checks, without historical limits. */
    public static byte[] certificateBytes(byte[] bytes) {
        certificateObject(bytes);
        Map<Integer, byte[]> f = fields(bytes,"73-CERT-FIELDS",new int[]{0x70,0x71,0xfe},Set.of());
        if (f.get(0x71)[0] == 0) return f.get(0x70);
        try (var input = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(f.get(0x70)))) {
            return input.readAllBytes();
        } catch (java.io.IOException e) { throw new AssertionError("73-CERT-FIELDS: malformed GZIP certificate",e); }
    }

    /** Section 3.1.7 structure only. Table 13 size interpretation awaits NIST review. */
    public static void securityObject(byte[] bytes) {
        String rule = "73-SECURITY-FIELDS";
        Map<Integer, byte[]> f = fields(bytes,rule,new int[]{0xba,0xbb,0xfe},Set.of());
        require(f.get(0xba).length % 3 == 0,rule,"mapping must contain complete three-byte entries");
    }

    /** Section 3.3.3 and Table 20, local structure only; does not access the URL. */
    public static void keyHistory(byte[] bytes) {
        String rule = "73-KEY-HISTORY";
        Map<Integer, byte[]> f = fields(bytes,rule,new int[]{0xc1,0xc2,0xf3,0xfe},Set.of(0xf3));
        length(f,0xc1,rule,1); length(f,0xc2,rule,1);
        int on = f.get(0xc1)[0] & 255, off = f.get(0xc2)[0] & 255;
        require(on + off <= 20,rule,"more than twenty retired key references");
        require(off == 0 || f.containsKey(0xf3),rule,"off-card certificates require URL");
        require(on + off != 0 || !f.containsKey(0xf3),rule,"zero counts prohibit URL");
        if (f.containsKey(0xf3)) {
            byte[] raw = f.get(0xf3);
            require(raw.length <= 118,rule,"URL exceeds 118 bytes");
            String url = new String(raw,StandardCharsets.US_ASCII);
            require(url.matches("(?i)http://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\\.?/[a-f0-9]{64}"),
                    rule,"URL must contain DNS name and SHA-256 hex digest");
        }
    }
}
